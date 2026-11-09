package main

import (
	"fmt"
	"log"
	"time"

	"github.com/session-warrant/session-warrant/agent/internal/bpfmap"
	"github.com/session-warrant/session-warrant/agent/internal/pb"
	"github.com/session-warrant/session-warrant/agent/internal/ringbuf"
	"github.com/session-warrant/session-warrant/agent/internal/store"
)

// kernelUpload is the ringbuf handler: every record is logged, and queued for the server when upstream is set
// (q nil = local only). kprobe mirror records go up too, with origin KPROBE, so the server can compare verdicts.
type kernelUpload struct{ q *store.AuditQueue }

func (k kernelUpload) record(r ringbuf.Record) {
	logRecord(r)
	if k.q == nil {
		return
	}
	off, err := bootOffset()
	if err == nil {
		var e *pb.AuditEvent
		if e, err = kernelEvent(r, off); err == nil {
			k.q.Append(e)
			return
		}
	}
	log.Printf("ringbuf: not uploaded: %v", err)
}

func (k kernelUpload) gap(g ringbuf.Gap) {
	logGap(g)
	if k.q == nil {
		return
	}
	off, err := bootOffset()
	if err != nil {
		log.Printf("ringbuf: gap not uploaded: %v", err)
		return
	}
	k.q.AppendGap(kernelGap(g, off))
}

// Kernel verdicts → proto AuditEvent for the audit stream. The kernel only knows boot time; the server partitions
// by wall time, so the conversion happens here (wall = boot + offset), like expires_ns in the other direction.

// Called per record: wall clock minus boot clock, now. Recomputed each time so a clock step shows up at once.
func bootOffset() (int64, error) {
	boot, err := bpfmap.BootNs()
	if err != nil {
		return 0, err
	}
	return time.Now().UnixNano() - int64(boot), nil
}

var selfProtectionKind = map[uint16]pb.SelfProtectionEvent_Kind{
	ringbuf.HookBPF:               pb.SelfProtectionEvent_KIND_BPF_SYSCALL,
	ringbuf.HookTaskKill:          pb.SelfProtectionEvent_KIND_KILL_PROTECTED,
	ringbuf.HookSbUmount:          pb.SelfProtectionEvent_KIND_UMOUNT_BPFFS,
	ringbuf.HookPtraceAccessCheck: pb.SelfProtectionEvent_KIND_PTRACE_UNTAGGED,
	ringbuf.HookKernelModuleReq:   pb.SelfProtectionEvent_KIND_MODULE_REQUEST,
}

// Called by the ringbuf handler. An event the server cannot read must not be sent: one payload-less
// event makes the server refuse the whole batch, and every later record waits behind it.
func kernelEvent(r ringbuf.Record, offset int64) (*pb.AuditEvent, error) {
	e := &pb.AuditEvent{
		Cpu:          r.CPU,
		CpuSeq:       r.CPUSeq,
		Hook:         pb.Hook(r.Hook),
		Verdict:      pb.Verdict(r.Verdict),
		Mode:         pb.Mode(r.Mode),
		BootTsNs:     r.BootTsNs,
		WallTsUnixNs: uint64(int64(r.BootTsNs) + offset),
		WarrantId:    r.WarrantID,
		SubjectId:    r.SubjectID,
		PolicyId:     r.PolicyID,
		TagSource:    pb.TagSource(r.TagSource),
		Origin:       pb.Origin(r.Origin),
		Process: &pb.ProcessIdentity{
			Pid: r.Proc.PID, Tgid: r.Proc.TGID, StartTimeNs: r.Proc.StartTimeNs, Ppid: r.Proc.PPID,
			Uid: r.Proc.UID, Euid: r.Proc.EUID, Gid: r.Proc.GID, Comm: r.Proc.Comm,
			CgroupId: r.Proc.CgroupID, PidNsInum: r.Proc.PIDNsInum,
		},
	}
	if kind, ok := selfProtectionKind[r.Hook]; ok {
		e.Payload = &pb.AuditEvent_SelfProtection{SelfProtection: &pb.SelfProtectionEvent{Kind: kind}}
		return e, nil
	}
	if err := payload(e, r); err != nil {
		return nil, fmt.Errorf("hook %d cpu %d seq %d: %w", r.Hook, r.CPU, r.CPUSeq, err)
	}
	return e, nil
}

func payload(e *pb.AuditEvent, r ringbuf.Record) error {
	switch r.Hook {
	case ringbuf.HookBprmCheckSecurity:
		x, ok := r.Exec()
		if !ok {
			return fmt.Errorf("exec payload")
		}
		e.Payload = &pb.AuditEvent_Exec{Exec: &pb.ExecEvent{File: ref(x.File), IMode: x.IMode, NewUid: x.NewUID, NewEuid: x.NewEUID}}
	case ringbuf.HookFileOpen:
		w, ok := r.Write()
		if !ok {
			return fmt.Errorf("write payload")
		}
		e.Payload = &pb.AuditEvent_FileWrite{FileWrite: &pb.FileWriteEvent{File: ref(w.File), Parent: ref(w.Parent), FFlags: w.FFlags}}
	case ringbuf.HookInodeCreate, ringbuf.HookInodeUnlink, ringbuf.HookInodeRename, ringbuf.HookInodeLink, ringbuf.HookInodeSymlink:
		m, ok := r.Inode()
		if !ok {
			return fmt.Errorf("inode payload")
		}
		ev := &pb.InodeMutateEvent{Op: pb.InodeMutateEvent_Op(m.Op), Dir: ref(m.Dir)}
		if m.Target.Ino != 0 {
			ev.NewDir = ref(m.Target)
		}
		e.Payload = &pb.AuditEvent_InodeMutate{InodeMutate: ev}
	case ringbuf.HookSocketConnect:
		c, ok := r.Connect()
		if !ok {
			return fmt.Errorf("connect payload")
		}
		e.Payload = &pb.AuditEvent_Connect{Connect: connect(c)}
	case ringbuf.HookSocketSendmsg:
		u, ok := r.UDPSend()
		if !ok {
			return fmt.Errorf("udp payload")
		}
		e.Payload = &pb.AuditEvent_UdpSend{UdpSend: &pb.UdpSendEvent{Destination: connect(u.Destination), Size: u.Size}}
	case ringbuf.HookSchedProcessFork:
		f, ok := r.Fork()
		if !ok {
			return fmt.Errorf("fork payload")
		}
		e.Payload = &pb.AuditEvent_Fork{Fork: &pb.ForkEvent{ChildPid: f.ChildTGID}}
	default:
		return fmt.Errorf("unknown hook")
	}
	return nil
}

func ref(f ringbuf.FileRef) *pb.FileRef {
	return &pb.FileRef{Dev: f.Dev, Ino: f.Ino}
}

// ringbuf has already unmapped ::ffff:a.b.c.d, so an IPv4 peer arrives as a 4-byte address.
func connect(c ringbuf.ConnectPayload) *pb.ConnectEvent {
	if !c.Addr.IsValid() {
		return &pb.ConnectEvent{Family: pb.ConnectEvent_FAMILY_UNIX, SunPath: c.UnixPath}
	}
	family := pb.ConnectEvent_FAMILY_INET6
	if c.Addr.Is4() {
		family = pb.ConnectEvent_FAMILY_INET
	}
	return &pb.ConnectEvent{Family: family, Addr: c.Addr.AsSlice(), Port: uint32(c.Port)}
}

// Called by the ringbuf gap callback. Both ends are records that did arrive; the lost ones lie between.
func kernelGap(g ringbuf.Gap, offset int64) *pb.GapReport {
	cause := pb.GapReport_CAUSE_CPU_SEQ_SKIP
	if v, ok := pb.GapReport_Cause_value["CAUSE_"+g.Cause]; ok {
		cause = pb.GapReport_Cause(v)
	}
	return &pb.GapReport{
		FromUnixNs:        uint64(int64(g.FromBootNs) + offset),
		ToUnixNs:          uint64(int64(g.ToBootNs) + offset),
		DroppedCount:      g.DroppedCount,
		DroppedCountKnown: g.Known,
		Cause:             cause,
	}
}
