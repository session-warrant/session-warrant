// warrantd — 노드 에이전트. 조립만 한다. 판정은 커널이 한다.
//
// 하는 일:
//   - main.go: 맵 · PAM 소켓 · ringbuf 를 열고, 종료 신호까지 돌린다. 감사 레코드와 Gap 을 로그로 남긴다
//   - binder.go: PAM 세션이 열리면 무영장 사유(NO_WARRANT · NO_KEY)를 기록하고, 닫히면 태그를 뗀다
//   - -upstream 이 있으면 무영장 세션을 메모리 큐에 쌓아 중앙으로 올린다 (store.AuditQueue → upstream.StreamAudit)
//
// 기동 순서 (바꾸지 말 것):
//  1. loader.Load     pin 된 맵이 있으면 재사용
//  2. store.Open      캐시된 영장을 맵에 복원
//  3. loader.AttachAll
//  4. pamsock.Listen  여기 전에 로그인한 세션은 태그가 없다 (유닛에 Before=sshd.service)
//  5. ringbuf · upstream  실패해도 죽지 않는다
//
// 지금은 4 · 5 만 붙어 있다. 1 · 3 은 bpftool 이 대신하고, 2 는 bbolt 대신 메모리 큐다.
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
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/session-warrant/session-warrant/agent/internal/bpfmap"
	"github.com/session-warrant/session-warrant/agent/internal/pamsock"
	"github.com/session-warrant/session-warrant/agent/internal/pb"
	"github.com/session-warrant/session-warrant/agent/internal/ringbuf"
	"github.com/session-warrant/session-warrant/agent/internal/store"
	"github.com/session-warrant/session-warrant/agent/internal/upstream"
)

const agentVersion = "warrantd 0.1.0-dev"

func main() {
	var (
		pinDir     = flag.String("pin-dir", "/sys/fs/bpf/warrant", "bpffs pin 경로")
		socketPath = flag.String("pam-socket", "/run/warrantd/pam.sock", "pam_warrant.so 가 보내는 소켓")
		statePath  = flag.String("state", "/var/lib/warrantd/state.db", "bbolt 경로")
		upstreamEP = flag.String("upstream", "", "중앙 gRPC 엔드포인트. 비어 있으면 로컬 전용")
	)
	flag.Parse()

	_ = statePath

	if err := run(*pinDir, *socketPath, *upstreamEP); err != nil {
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
func nodeHello() *pb.NodeHello {
	h := &pb.NodeHello{AgentVersion: agentVersion}
	h.Hostname, _ = os.Hostname()

	var u unix.Utsname
	if unix.Uname(&u) == nil {
		h.KernelVersion = unix.ByteSliceToString(u.Release[:])
	}
	if lsm, err := os.ReadFile("/sys/kernel/security/lsm"); err == nil {
		h.BpfLsmEnabled = strings.Contains(","+strings.TrimSpace(string(lsm))+",", ",bpf,")
	}
	var up unix.Timespec
	if unix.ClockGettime(unix.CLOCK_BOOTTIME, &up) == nil {
		h.BootedAtUnixNs = uint64(time.Now().UnixNano() - up.Nano())
	}
	return h
}

// Starts all components and blocks until shutdown; returns so deferred Closes run.
func run(pinDir, socketPath, upstreamEP string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	maps, err := bpfmap.Open(pinDir)
	if err != nil {
		return fmt.Errorf("open maps %s: %w", pinDir, err)
	}
	defer maps.Close()

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

	b := &binder{maps: maps}

	// Upstream failing never stops warrantd: tagging and the kernel keep working (§17).
	if upstreamEP != "" {
		client, err := upstream.Dial(upstreamEP, "", "", "")
		if err != nil {
			log.Printf("upstream: %v (running local only)", err)
		} else {
			defer client.Close()
			q := store.NewAuditQueue(10_000, 500)
			b.audit = q
			go client.StreamAudit(ctx, nodeHello(), q)
		}
	}

	serveErr := make(chan error, 1)

	go func() { serveErr <- srv.Serve(ctx, b) }()

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
