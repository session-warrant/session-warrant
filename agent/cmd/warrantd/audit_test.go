package main

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/session-warrant/session-warrant/agent/internal/pb"
	"github.com/session-warrant/session-warrant/agent/internal/ringbuf"
)

// Payload layouts as the kernel writes them (bpf/warrant.bpf.h). ringbuf owns decoding; these only build input.
type tFileRef struct {
	Dev uint32
	_   uint32
	Ino uint64
}
type tExec struct {
	File            tFileRef
	IMode, UID, EID uint32
	_               uint32
}
type tWrite struct {
	File, Parent tFileRef
	FFlags       uint32
	_            uint32
}
type tInode struct {
	Dir, Target tFileRef
	Op          uint8
	_           [7]byte
}
type tConnect struct {
	Family, Proto uint8
	Port          uint16
	_             uint32
	Addr          [16]byte
}
type tUDP struct {
	Dst  tConnect
	Size uint64
}
type tFork struct {
	ParentTGID, ChildTGID uint32
	ChildCgroupID         uint64
}

func raw(t *testing.T, payload any) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := binary.Write(&b, binary.LittleEndian, payload); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

const offset = int64(1_790_000_000_000_000_000) // wall clock = boot clock + offset

func rec(hook uint16, payload []byte) ringbuf.Record {
	return ringbuf.Record{
		CPU: 3, CPUSeq: 41, Hook: hook, Verdict: 2, Mode: 1, Origin: 1, TagSource: 1,
		BootTsNs: 5_000, WarrantID: 8, SubjectID: 3, PolicyID: 9,
		Proc: ringbuf.Process{PID: 40, TGID: 40, PPID: 39, UID: 1000, EUID: 0, GID: 1000, PIDNsInum: 4026531836,
			StartTimeNs: 77, CgroupID: 59020, Comm: "touch"},
		PayloadRaw: payload,
	}
}

// 서버는 벽시계(wall_ts_unix_ns)를 파티션 키로 쓴다. 커널은 boot 시각만 안다 — 변환은 warrantd 가 한다.
func TestKernelEventCarriesCommonFieldsAndWallTime(t *testing.T) {
	e, err := kernelEvent(rec(ringbuf.HookBprmCheckSecurity, raw(t, tExec{File: tFileRef{Dev: 2049, Ino: 131}, IMode: 0o104755})), offset)
	if err != nil {
		t.Fatal(err)
	}
	if e.GetWallTsUnixNs() != uint64(offset+5_000) || e.GetBootTsNs() != 5_000 {
		t.Fatalf("time boot %d wall %d", e.GetBootTsNs(), e.GetWallTsUnixNs())
	}
	if e.GetHook() != pb.Hook_HOOK_BPRM_CHECK_SECURITY || e.GetVerdict() != pb.Verdict_VERDICT_WOULD_DENY ||
		e.GetMode() != pb.Mode_MODE_DRYRUN || e.GetOrigin() != pb.Origin_ORIGIN_LSM || e.GetTagSource() != pb.TagSource_TAG_CGROUP {
		t.Fatalf("enums %v %v %v %v %v", e.GetHook(), e.GetVerdict(), e.GetMode(), e.GetOrigin(), e.GetTagSource())
	}
	if e.GetWarrantId() != 8 || e.GetSubjectId() != 3 || e.GetPolicyId() != 9 || e.GetCpu() != 3 || e.GetCpuSeq() != 41 {
		t.Fatalf("ids %v", e)
	}
	p := e.GetProcess()
	if p.GetTgid() != 40 || p.GetPpid() != 39 || p.GetUid() != 1000 || p.GetCgroupId() != 59020 || p.GetComm() != "touch" {
		t.Fatalf("process %v", p)
	}
	x := e.GetExec()
	if x.GetFile().GetDev() != 2049 || x.GetFile().GetIno() != 131 || x.GetIMode() != 0o104755 {
		t.Fatalf("exec %v", x)
	}
}

func TestKernelEventPayloadPerHook(t *testing.T) {
	v4 := [16]byte{10: 0xff, 11: 0xff, 12: 1, 13: 1, 14: 1, 15: 1} // ::ffff:1.1.1.1
	unix := [16]byte{}
	copy(unix[:], "/run/dbus/syste")

	cases := []struct {
		name  string
		hook  uint16
		raw   []byte
		check func(*testing.T, *pb.AuditEvent)
	}{
		{"쓰기", ringbuf.HookFileOpen, raw(t, tWrite{File: tFileRef{Dev: 1, Ino: 2}, Parent: tFileRef{Dev: 1, Ino: 3}, FFlags: 0o101}),
			func(t *testing.T, e *pb.AuditEvent) {
				if w := e.GetFileWrite(); w.GetFile().GetIno() != 2 || w.GetParent().GetIno() != 3 || w.GetFFlags() != 0o101 {
					t.Fatalf("write %v", w)
				}
			}},
		{"rename", ringbuf.HookInodeRename, raw(t, tInode{Dir: tFileRef{Dev: 1, Ino: 5}, Target: tFileRef{Dev: 1, Ino: 6}, Op: 3}),
			func(t *testing.T, e *pb.AuditEvent) {
				if m := e.GetInodeMutate(); m.GetOp() != pb.InodeMutateEvent_OP_RENAME || m.GetDir().GetIno() != 5 || m.GetNewDir().GetIno() != 6 {
					t.Fatalf("inode %v", m)
				}
			}},
		{"IPv4 접속", ringbuf.HookSocketConnect, raw(t, tConnect{Family: 10, Proto: 1, Port: 443, Addr: v4}),
			func(t *testing.T, e *pb.AuditEvent) {
				c := e.GetConnect()
				if c.GetFamily() != pb.ConnectEvent_FAMILY_INET || c.GetPort() != 443 || !bytes.Equal(c.GetAddr(), netip.MustParseAddr("1.1.1.1").AsSlice()) {
					t.Fatalf("connect %v", c)
				}
			}},
		{"유닉스 소켓", ringbuf.HookSocketConnect, raw(t, tConnect{Family: 1, Addr: unix}),
			func(t *testing.T, e *pb.AuditEvent) {
				if c := e.GetConnect(); c.GetFamily() != pb.ConnectEvent_FAMILY_UNIX || c.GetSunPath() != "/run/dbus/syste" {
					t.Fatalf("connect %v", c)
				}
			}},
		{"UDP", ringbuf.HookSocketSendmsg, raw(t, tUDP{Dst: tConnect{Family: 10, Proto: 2, Port: 53, Addr: v4}, Size: 64}),
			func(t *testing.T, e *pb.AuditEvent) {
				if u := e.GetUdpSend(); u.GetSize() != 64 || u.GetDestination().GetPort() != 53 {
					t.Fatalf("udp %v", u)
				}
			}},
		{"fork", ringbuf.HookSchedProcessFork, raw(t, tFork{ParentTGID: 40, ChildTGID: 41, ChildCgroupID: 59020}),
			func(t *testing.T, e *pb.AuditEvent) {
				if f := e.GetFork(); f.GetChildPid() != 41 {
					t.Fatalf("fork %v", f)
				}
			}},
		{"자기보호 ptrace", ringbuf.HookPtraceAccessCheck, nil,
			func(t *testing.T, e *pb.AuditEvent) {
				if s := e.GetSelfProtection(); s.GetKind() != pb.SelfProtectionEvent_KIND_PTRACE_UNTAGGED {
					t.Fatalf("self-protection %v", s)
				}
			}},
		{"자기보호 bpf", ringbuf.HookBPF, nil,
			func(t *testing.T, e *pb.AuditEvent) {
				if s := e.GetSelfProtection(); s.GetKind() != pb.SelfProtectionEvent_KIND_BPF_SYSCALL {
					t.Fatalf("self-protection %v", s)
				}
			}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, err := kernelEvent(rec(c.hook, c.raw), offset)
			if err != nil {
				t.Fatal(err)
			}
			c.check(t, e)
		})
	}
}

// 서버는 payload 없는 이벤트를 받으면 묶음 전체를 거부한다 — 그러면 그 뒤 기록이 전부 막힌다. 보내지 않는다.
func TestKernelEventRefusesWhatItCannotDecode(t *testing.T) {
	if _, err := kernelEvent(rec(ringbuf.HookBprmCheckSecurity, []byte{1, 2}), offset); err == nil {
		t.Fatal("converted a truncated exec payload")
	}
	if _, err := kernelEvent(rec(99, nil), offset); err == nil {
		t.Fatal("converted an unknown hook")
	}
}

func TestKernelGapIsInWallTime(t *testing.T) {
	g := kernelGap(ringbuf.Gap{FromBootNs: 1_000, ToBootNs: 9_000, DroppedCount: 7, Known: true, Cause: "CPU_SEQ_SKIP"}, offset)
	if g.GetFromUnixNs() != uint64(offset+1_000) || g.GetToUnixNs() != uint64(offset+9_000) ||
		g.GetDroppedCount() != 7 || !g.GetDroppedCountKnown() || g.GetCause() != pb.GapReport_CAUSE_CPU_SEQ_SKIP {
		t.Fatalf("gap %v", g)
	}
	if kernelGap(ringbuf.Gap{FromBootNs: 1, ToBootNs: 2, Cause: "RINGBUF_OVERFLOW"}, offset).GetCause() != pb.GapReport_CAUSE_RINGBUF_OVERFLOW {
		t.Fatal("cause")
	}
}
