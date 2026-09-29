// Package ringbuf 는 커널 events ringbuf 를 소비한다. 유실은 Gap 으로 드러낸다.
package ringbuf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

// Process 는 이벤트를 낸 프로세스다. proto/audit.proto 의 ProcessIdentity 에 대응한다.
//
// Comm 은 16바이트로 잘리고 위조 가능하다 — 1급 증거가 아니다.
// 신뢰할 수 있는 신원은 (PID, StartTimeNs) 쌍이고 파일 증거는 (dev, ino) 다 (§14).
type Process struct {
	PID         uint32
	TGID        uint32
	PPID        uint32
	UID         uint32
	EUID        uint32
	GID         uint32
	PIDNsInum   uint32 // exit 중이면 0
	StartTimeNs uint64
	CgroupID    uint64
	Comm        string
}

type Record struct {
	CPU        uint32
	CPUSeq     uint64 // (cpu, cpu_seq) 가 건너뛰면 유실
	Hook       uint16
	Verdict    uint8
	Mode       uint8
	Origin     uint8
	TagSource  uint8
	BootTsNs   uint64
	WarrantID  uint64
	SubjectID  uint32
	PolicyID   uint32
	Proc       Process
	PayloadRaw []byte
}

// FileRef 가 1급 증거다. 경로는 참고일 뿐이다 (§14).
type FileRef struct {
	Dev uint32
	Ino uint64
}

type ExecPayload struct {
	File    FileRef
	IMode   uint32 // setuid 탐지
	NewUID  uint32
	NewEUID uint32
}

type WritePayload struct {
	File   FileRef
	Parent FileRef
	FFlags uint32
}

type InodePayload struct {
	Dir    FileRef
	Target FileRef
	Op     uint8
}

type ConnectPayload struct {
	Family uint8
	Proto  uint8
	Port   uint16
	Addr   netip.Addr // AF_UNIX 면 IsValid()==false — UnixPath 를 본다
	// AF_UNIX 의 sun_path 앞부분. 위임 경로 차단에서만 실린다.
	UnixPath string
}

type ForkPayload struct {
	ParentTGID    uint32
	ChildTGID     uint32
	ChildCgroupID uint64
}

// Gap 은 감사 기록이 끊긴 구간이다. 숨기지 않고 그대로 올려보낸다 (§13).
type Gap struct {
	FromUnixNs   uint64
	ToUnixNs     uint64
	DroppedCount uint64
	Known        bool
	Cause        string // RINGBUF_OVERFLOW · AGENT_DOWN · LOCAL_STORE_FULL · CPU_SEQ_SKIP
}

type Consumer struct {
	rd   *ringbuf.Reader
	m    *ebpf.Map
	once sync.Once

	dropped atomic.Uint64

	mu    sync.Mutex
	next  map[uint32]uint64 // cpu → 다음에 올 cpu_seq
	onGap func(Gap)
}

func Open(pinDir string) (*Consumer, error) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, "events"), nil)
	if err != nil {
		return nil, fmt.Errorf("pin 된 맵 events: %w", err)
	}
	rd, err := ringbuf.NewReader(m)
	if err != nil {
		_ = m.Close()
		return nil, fmt.Errorf("ringbuf reader: %w", err)
	}
	return &Consumer{rd: rd, m: m, next: make(map[uint32]uint64)}, nil
}

// OnGap 은 유실 구간을 받을 콜백을 단다. Run 전에 부른다.
func (c *Consumer) OnGap(f func(Gap)) { c.onGap = f }

// Run 의 handler 는 네트워크를 기다리지 않는다. 느리면 커널이 드롭한다.
func (c *Consumer) Run(ctx context.Context, handler func(Record)) error {
	go func() {
		<-ctx.Done()
		_ = c.rd.Close()
	}()

	for {
		rec, err := c.rd.Read()
		if err != nil {
			if errors.Is(err, os.ErrClosed) || errors.Is(err, ringbuf.ErrClosed) {
				return ctx.Err()
			}
			return fmt.Errorf("ringbuf read: %w", err)
		}

		r, err := decode(rec.RawSample)
		if err != nil {
			// 레코드 하나가 깨졌다고 소비를 멈추지 않는다. 다만 유실로 센다.
			c.dropped.Add(1)
			continue
		}
		c.checkGap(r)
		handler(r)
	}
}

// DroppedTotal 은 누적 유실 건수다. 커널이 ringbuf 가 차서 버린 것은 cpu_seq 가
// 건너뛴 것으로 드러난다 — 그래서 커널이 reserve 전에 번호를 올린다.
func (c *Consumer) DroppedTotal() uint64 { return c.dropped.Load() }

func (c *Consumer) Close() error {
	var err error
	c.once.Do(func() {
		err = errors.Join(c.rd.Close(), c.m.Close())
	})
	return err
}

// checkGap 은 (cpu, cpu_seq) 의 연속성을 본다.
func (c *Consumer) checkGap(r Record) {
	c.mu.Lock()
	want, seen := c.next[r.CPU]
	c.next[r.CPU] = r.CPUSeq + 1
	c.mu.Unlock()

	if !seen || r.CPUSeq < want {
		return // 첫 레코드이거나 번호가 되돌아갔다. 여기서 유실을 단정하지 않는다
	}
	missing := r.CPUSeq - want
	if missing == 0 {
		return
	}
	c.dropped.Add(missing)
	if c.onGap != nil {
		c.onGap(Gap{
			ToUnixNs:     r.BootTsNs,
			DroppedCount: missing,
			Known:        true,
			Cause:        "CPU_SEQ_SKIP",
		})
	}
}

// ── 디코딩 ────────────────────────────────────────────────────────

var headerSize = binary.Size(evtHeader{})

func decode(raw []byte) (Record, error) {
	if len(raw) < headerSize {
		return Record{}, fmt.Errorf("레코드가 %d바이트뿐이다 (머리 %d바이트)", len(raw), headerSize)
	}
	var h evtHeader
	if err := binary.Read(bytes.NewReader(raw[:headerSize]), binary.LittleEndian, &h); err != nil {
		return Record{}, err
	}

	end := headerSize + int(h.PayloadLen)
	if end > len(raw) {
		return Record{}, fmt.Errorf("payload_len=%d 인데 레코드는 %d바이트다", h.PayloadLen, len(raw))
	}

	return Record{
		CPU:       h.CPU,
		CPUSeq:    h.CPUSeq,
		Hook:      h.Hook,
		Verdict:   h.Verdict,
		Mode:      h.Mode,
		Origin:    h.Origin,
		TagSource: h.TagSource,
		BootTsNs:  h.BootTsNs,
		WarrantID: h.WarrantID,
		SubjectID: h.SubjectID,
		PolicyID:  h.PolicyID,
		Proc: Process{
			PID:         h.Proc.PID,
			TGID:        h.Proc.TGID,
			PPID:        h.Proc.PPID,
			UID:         h.Proc.UID,
			EUID:        h.Proc.EUID,
			GID:         h.Proc.GID,
			PIDNsInum:   h.Proc.PIDNsInum,
			StartTimeNs: h.Proc.StartTimeNs,
			CgroupID:    h.Proc.CgroupID,
			Comm:        cstr(h.Proc.Comm[:]),
		},
		PayloadRaw: raw[headerSize:end],
	}, nil
}

// Exec 은 BPRM_CHECK_SECURITY 레코드의 payload 를 푼다.
func (r Record) Exec() (ExecPayload, bool) {
	var p plExec
	if r.Hook != HookBprmCheckSecurity || !unpack(r.PayloadRaw, &p) {
		return ExecPayload{}, false
	}
	return ExecPayload{
		File:    FileRef{Dev: p.File.Dev, Ino: p.File.Ino},
		IMode:   p.IMode,
		NewUID:  p.NewUID,
		NewEUID: p.NewEUID,
	}, true
}

// Write 는 FILE_OPEN 레코드의 payload 를 푼다.
func (r Record) Write() (WritePayload, bool) {
	var p plWrite
	if r.Hook != HookFileOpen || !unpack(r.PayloadRaw, &p) {
		return WritePayload{}, false
	}
	return WritePayload{
		File:   FileRef{Dev: p.File.Dev, Ino: p.File.Ino},
		Parent: FileRef{Dev: p.Parent.Dev, Ino: p.Parent.Ino},
		FFlags: p.FFlags,
	}, true
}

// Inode 는 inode_* 다섯 훅의 payload 를 푼다.
func (r Record) Inode() (InodePayload, bool) {
	switch r.Hook {
	case HookInodeCreate, HookInodeUnlink, HookInodeRename, HookInodeLink, HookInodeSymlink:
	default:
		return InodePayload{}, false
	}
	var p plInode
	if !unpack(r.PayloadRaw, &p) {
		return InodePayload{}, false
	}
	return InodePayload{
		Dir:    FileRef{Dev: p.Dir.Dev, Ino: p.Dir.Ino},
		Target: FileRef{Dev: p.Target.Dev, Ino: p.Target.Ino},
		Op:     p.Op,
	}, true
}

// Connect 는 SOCKET_CONNECT · SOCKET_SENDMSG 의 payload 를 푼다.
func (r Record) Connect() (ConnectPayload, bool) {
	if r.Hook != HookSocketConnect && r.Hook != HookSocketSendmsg {
		return ConnectPayload{}, false
	}
	var p plConnect
	if !unpack(r.PayloadRaw, &p) {
		return ConnectPayload{}, false
	}
	out := ConnectPayload{Family: p.Family, Proto: p.Proto, Port: p.Port}
	switch p.Family {
	case 1: // AF_UNIX — 주소 자리에 경로 앞부분이 실린다
		out.UnixPath = cstr(p.Addr[:])
	case 2, 10:
		a := netip.AddrFrom16(p.Addr)
		if a.Is4In6() {
			a = a.Unmap()
		}
		out.Addr = a
	}
	return out, true
}

// Fork 는 SCHED_PROCESS_FORK 의 payload 를 푼다.
func (r Record) Fork() (ForkPayload, bool) {
	var p plFork
	if r.Hook != HookSchedProcessFork || !unpack(r.PayloadRaw, &p) {
		return ForkPayload{}, false
	}
	return ForkPayload(p), true
}

func unpack(raw []byte, dst any) bool {
	n := binary.Size(dst)
	if n < 0 || len(raw) < n {
		return false
	}
	return binary.Read(bytes.NewReader(raw[:n]), binary.LittleEndian, dst) == nil
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
