// warrantd — 노드 에이전트. 조립만 한다. 판정은 커널이 한다.
//
// 하는 일:
//   - main.go: BPF 를 올려 훅에 붙이고, 맵 · PAM 소켓 · ringbuf 를 열고, 종료 신호까지 돌린다. 감사 레코드와 Gap 을 로그로 남긴다
//   - warrants.go: -warrants 파일의 영장을 정책 → 규칙 → 영장 순으로 맵에 넣고 active_flag 를 켠다
//   - binder.go: PAM 세션이 열리면 계정 · 키가 맞는 영장을 cgroup 에 붙이고, 없으면 무영장 사유를 기록한다. 닫히면 태그를 뗀다
//   - -upstream 이 있으면 무영장 세션을 메모리 큐에 쌓아 중앙으로 올린다 (store.AuditQueue → upstream.StreamAudit)
//
// 기동 순서 (바꾸지 말 것):
//  1. loader.Load     pin 된 맵이 있으면 재사용
//  2. 영장 설치       지금은 -warrants 로컬 파일. 나중에 store.Open 이 캐시된 영장을 복원한다
//  3. loader.AttachAll
//  4. pamsock.Listen  여기 전에 로그인한 세션은 태그가 없다 (유닛에 Before=sshd.service)
//  5. ringbuf · upstream  실패해도 죽지 않는다
//
// 중앙 발급(upstream.Subscribe)과 bbolt 캐시는 아직 없다. 감사는 메모리 큐다.
// 종료할 때 pin 은 지우지 않는다.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/session-warrant/session-warrant/agent/internal/bpfmap"
	"github.com/session-warrant/session-warrant/agent/internal/loader"
	"github.com/session-warrant/session-warrant/agent/internal/pamsock"
	"github.com/session-warrant/session-warrant/agent/internal/pb"
	"github.com/session-warrant/session-warrant/agent/internal/policy"
	"github.com/session-warrant/session-warrant/agent/internal/ringbuf"
	"github.com/session-warrant/session-warrant/agent/internal/store"
	"github.com/session-warrant/session-warrant/agent/internal/upstream"
)

const agentVersion = "warrantd 0.1.0-dev"

func main() {
	var (
		pinDir     = flag.String("pin-dir", "/sys/fs/bpf/warrant", "bpffs pin 경로")
		objPath    = flag.String("bpf-obj", "/usr/lib/warrant/warrant.bpf.o", "BPF 오브젝트 경로")
		socketPath = flag.String("pam-socket", "/run/warrantd/pam.sock", "pam_warrant.so 가 보내는 소켓")
		statePath  = flag.String("state", "/var/lib/warrantd/state.db", "bbolt 경로")
		upstreamEP = flag.String("upstream", "", "중앙 gRPC 엔드포인트. 비어 있으면 로컬 전용")
		warrantsAt = flag.String("warrants", "/etc/warrantd/warrants.json", "로컬 영장 파일 (Warrant JSON 배열). 없으면 영장 없이 돈다")
	)
	flag.Parse()

	_ = statePath

	if err := run(*pinDir, *objPath, *socketPath, *upstreamEP, *warrantsAt); err != nil {
		log.Printf("warrantd: %v", err)
		os.Exit(1)
	}
}

// Logs one line per kernel verdict; skips kprobe mirror duplicates.
func logRecord(r ringbuf.Record) {
	if r.Origin == 2 {
		return
	}
	hook := ringbuf.HookName(r.Hook)
	verdict := ringbuf.VerdictName(r.Verdict, r.Mode)

	warrant := r.WarrantID
	cgroup := r.Proc.CgroupID
	pid := r.Proc.PID
	comm := r.Proc.Comm

	log.Printf("ringbuf: hook=%s verdict=%s warrant=%d cgroup=%d pid=%d comm=%q", hook, verdict, warrant, cgroup, pid, comm)
	// TODO (나중): 훅별 payload — r.Exec(), r.Write(), r.Connect() 등은 (값, ok) 를 돌려준다
	//   switch 로 훅마다 하나씩. 0단계에서는 없어도 된다

}

// Called by cons.Run when cpu_seq skips.
// Logs the lost range; a gap must never look like a quiet period (§13).
func logGap(g ringbuf.Gap) {
	log.Printf("ringbuf: GAP dropped=%d cause=%s known=%t from=%d to=%d",
		g.DroppedCount, g.Cause, g.Known, g.FromUnixNs, g.ToUnixNs)
}

// Sent as the first batch of every audit stream; the server registers the node from it.
func nodeHello(hooks []pb.Hook) *pb.NodeHello {
	h := &pb.NodeHello{AgentVersion: agentVersion, AttachedHooks: hooks, BpfLsmEnabled: true}
	h.Hostname, _ = os.Hostname()

	var u unix.Utsname
	if unix.Uname(&u) == nil {
		h.KernelVersion = unix.ByteSliceToString(u.Release[:])
	}
	var up unix.Timespec
	if unix.ClockGettime(unix.CLOCK_BOOTTIME, &up) == nil {
		h.BootedAtUnixNs = uint64(time.Now().UnixNano() - up.Nano())
	}
	return h
}

// Starts all components and blocks until shutdown; returns so deferred Closes run.
func run(pinDir, objPath, socketPath, upstreamEP, warrantsPath string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// lsm/* cannot attach without bpf in the boot LSM list; say so instead of a raw attach error.
	if on, err := loader.BpfLsmEnabled(); err != nil {
		return err
	} else if !on {
		return errors.New("bpf LSM is off: run deploy/enable-bpf-lsm.sh and reboot")
	}

	// Pinned maps are reused, so a restart keeps every session's tag. Close leaves the pins.
	ld, err := loader.LoadObject(objPath, pinDir)
	if err != nil {
		return err
	}
	defer ld.Close()

	maps, err := bpfmap.Open(pinDir)
	if err != nil {
		return fmt.Errorf("open maps %s: %w", pinDir, err)
	}
	defer maps.Close()

	warrants, specs, compiled := setupWarrants(maps, warrantsPath)

	// Pinned links are picked up, so a restart never hangs a second copy on a hook.
	if err := ld.AttachAll(); err != nil {
		return fmt.Errorf("attach: %w", err)
	}
	attached := ld.AttachedHooks()
	if len(attached) != ld.ProgramCount() {
		return fmt.Errorf("attach: %d of %d programs", len(attached), ld.ProgramCount())
	}
	log.Printf("warrantd: %d hooks attached, pinned at %s", len(attached), pinDir)

	srv, err := pamsock.Listen(socketPath)
	if err != nil {
		return err
	}

	cons, err := ringbuf.Open(pinDir)

	runErr := make(chan error, 1)

	if err == nil {
		defer cons.Close()
		cons.OnGap(logGap)
		go func() { runErr <- cons.Run(ctx, logRecord) }()
	} else {
		log.Printf("ringbuf: open %s: %v", pinDir, err)
	}

	b := &binder{maps: maps, warrants: warrants}

	if len(compiled) > 0 {
		if w, err := watchPolicies(maps, specs, compiled); err != nil {
			log.Printf("warrants: watcher: %v", err)
		} else {
			defer w.Close()
		}
	}

	// Upstream failing never stops warrantd: tagging and the kernel keep working (§17).
	if upstreamEP != "" {
		client, err := upstream.Dial(upstreamEP, "", "", "")
		if err != nil {
			log.Printf("upstream: %v (running local only)", err)
		} else {
			defer client.Close()
			q := store.NewAuditQueue(10_000, 500)
			b.audit = q
			go client.StreamAudit(ctx, nodeHello(hooksFromSections(attached)), q)
		}
	}

	serveErr := make(chan error, 1)

	go func() { serveErr <- srv.Serve(ctx, b) }()

	// The socket is bound by Listen, so sessions from here on are tagged. Only now may sshd start.
	if err := sdNotify("READY=1"); err != nil {
		log.Printf("warrantd: sd_notify: %v", err)
	}

	for {
		select {
		case <-ctx.Done():
			return <-serveErr
		case err := <-serveErr:
			return err
		case err := <-runErr:
			if errors.Is(err, context.Canceled) {
				continue
			}
			log.Printf("ringbuf: run: %v", err)
		}
	}

}

// Called by run before attach. Turns active_flag on only when a warrant is installed.
func setupWarrants(maps *bpfmap.Maps, path string) ([]*pb.Warrant, map[uint32]policy.Spec, []*policy.Compiled) {
	host, _ := os.Hostname()
	ws, err := loadWarrants(path, host)
	if err != nil {
		log.Printf("warrants: %v (running without warrants)", err)
	}
	installed, specs, compiled := installWarrants(maps, ws)

	if err := maps.SetActive(len(installed) > 0); err != nil {
		log.Printf("warrants: %v", err)
	}
	log.Printf("warrants: %d installed from %s, active=%t", len(installed), path, len(installed) > 0)
	return installed, specs, compiled
}

// Called by run. Recompiles a policy when a rule's file is replaced, or its rules silently stop matching (S4).
func watchPolicies(maps *bpfmap.Maps, specs map[uint32]policy.Spec, compiled []*policy.Compiled) (*policy.Watcher, error) {
	w, err := policy.NewWatcher()
	if err != nil {
		return nil, err
	}
	_ = w.OnChange(func(id uint32) {
		c, err := policy.Compile(id, specs[id])
		if err == nil {
			err = c.Apply(maps)
		}
		if err != nil {
			log.Printf("warrants: policy %d changed on disk, recompile: %v", id, err)
			return
		}
		log.Printf("warrants: policy %d changed on disk, recompiled", id)
		_ = w.Watch(c)
	})
	for _, c := range compiled {
		_ = w.Watch(c)
	}
	return w, nil
}
