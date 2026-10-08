// warrantctl — 커널 파트 개발 하네스. 버리는 코드다.
//
// warrantd 가 할 일(발급 · 감사 업로드)을 손으로 흉내 내서 커널 판정만 본다.
// 맵 접근은 전부 internal/bpfmap 을 거친다 — 여기서 직접 열지 않는다.
//
//	sudo ./warrantctl -pin-dir /sys/fs/bpf/wmaps -bind-cgroup 1234 -mode enforce \
//	     -allow-exec /usr/bin/true,/bin/sh -allow-write /tmp/wt -deny-write /tmp/wt/secret
//
// 맵은 미리 만들어져 있어야 한다 (loader 가 아직 없으므로 bpftool 로):
//
//	sudo bpftool prog loadall bpf/warrant.bpf.o /sys/fs/bpf/wtest \
//	     pinmaps /sys/fs/bpf/wmaps autoattach
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/session-warrant/session-warrant/agent/internal/bpfmap"
	"github.com/session-warrant/session-warrant/agent/internal/policy"
	"github.com/session-warrant/session-warrant/agent/internal/ringbuf"
)

const (
	warrantID = 1
	policyID  = 7
	subjectID = 42
)

func main() {
	var (
		pinDir     = flag.String("pin-dir", "/sys/fs/bpf/wmaps", "pin 된 맵 경로")
		bindCgroup = flag.Uint64("bind-cgroup", 0, "이 cgroup id 에 영장을 건다")
		mode       = flag.String("mode", "observe", "observe · dryrun · enforce")
		allowExec  = flag.String("allow-exec", "", "실행 허용 경로 (쉼표로 구분)")
		allowWrite = flag.String("allow-write", "", "쓰기 허용 디렉터리 (재귀)")
		denyWrite  = flag.String("deny-write", "", "쓰기 금지 디렉터리 (재귀)")
		allowNet   = flag.String("allow-net", "", "아웃바운드 허용 CIDR")
		expireIn   = flag.Duration("expire-in", 0, "이만큼 뒤에 만료. 0 이면 만료 없음")
		revokeIn   = flag.Duration("revoke-in", 0, "이만큼 뒤에 취소")
		breakGlass = flag.Bool("break-glass", false, "자기보호를 푸는 비상용 영장")
		active     = flag.Bool("active", true, "노드 전역 스위치")
		mirror     = flag.Bool("mirror", false, "kprobe 미러 기록도 같이 찍는다")
		noColor    = flag.Bool("no-color", false, "색 끄기")
	)
	flag.Parse()

	if err := run(*pinDir, opts{
		cgroup:     *bindCgroup,
		mode:       *mode,
		allowExec:  split(*allowExec),
		allowWrite: split(*allowWrite),
		denyWrite:  split(*denyWrite),
		allowNet:   split(*allowNet),
		expireIn:   *expireIn,
		revokeIn:   *revokeIn,
		breakGlass: *breakGlass,
		active:     *active,
		mirror:     *mirror,
		color:      !*noColor && isTTY(os.Stderr),
	}); err != nil {
		fmt.Fprintln(os.Stderr, "오류:", err)
		os.Exit(1)
	}
}

type opts struct {
	cgroup                                     uint64
	mode                                       string
	allowExec, allowWrite, denyWrite, allowNet []string
	expireIn, revokeIn                         time.Duration
	breakGlass, active, mirror, color          bool
}

func run(pinDir string, o opts) error {
	m, err := bpfmap.Open(pinDir)
	if err != nil {
		return err
	}
	defer m.Close()

	md, err := parseMode(o.mode)
	if err != nil {
		return err
	}

	w := bpfmap.Warrant{
		SubjectID: subjectID,
		PolicyID:  policyID,
		Mode:      md,
	}
	if o.breakGlass {
		w.BreakGlass = 1
	}
	if o.expireIn > 0 {
		now, err := bpfmap.BootNs()
		if err != nil {
			return err
		}
		w.ExpiresNs = now + uint64(o.expireIn)
	}
	if err := m.PutWarrant(warrantID, w); err != nil {
		return err
	}

	// 규칙은 policy 를 거친다. 경로→inode 변환도, 기본 허용 세트도,
	// 위험한 조합 경고도 전부 거기 있다 — 여기서 맵에 직접 쓰지 않는다.
	spec := policy.Spec{Name: "warrantctl"}
	for _, x := range o.allowExec {
		spec.ExecRules = append(spec.ExecRules, policy.ExecRule{Path: x})
	}
	for _, x := range o.allowWrite {
		spec.WriteRules = append(spec.WriteRules,
			policy.WriteRule{Path: x, Effect: policy.EffectAllow, Recursive: true})
	}
	for _, x := range o.denyWrite {
		spec.WriteRules = append(spec.WriteRules,
			policy.WriteRule{Path: x, Effect: policy.EffectDeny, Recursive: true})
	}
	for _, x := range o.allowNet {
		spec.NetRules = append(spec.NetRules, policy.NetRule{CIDR: x})
	}

	compiled, err := policy.Compile(policyID, spec)
	if err != nil {
		return err
	}
	for _, msg := range compiled.Warnings {
		fmt.Fprintf(os.Stderr, "  %s %s\n", paint(o.color, cAmber, "경고"), msg)
	}
	if err := compiled.Apply(m); err != nil {
		return err
	}

	// 이름 표에 담아두면 로그에서 inode 대신 경로가 보인다.
	names := map[bpfmap.FileRef]string{}
	for _, src := range compiled.Sources {
		names[src.Ref] = src.Path
	}
	logf(o.color, "  규칙 %d개 (실행 %d · 쓰기 %d · 네트워크 %d)",
		len(compiled.Sources), len(compiled.Exec), len(compiled.Write), len(compiled.Net))

	if o.cgroup != 0 {
		if err := m.TagCgroup(o.cgroup, warrantID); err != nil {
			return err
		}
		logf(o.color, "  cgroup %d -> 영장 %d (mode=%s)", o.cgroup, warrantID, o.mode)
	}
	if err := m.SetActive(o.active); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if o.expireIn > 0 {
		logf(o.color, "  만료 예정: %s 뒤", o.expireIn)
	}
	if o.revokeIn > 0 {
		logf(o.color, "  취소 예정: %s 뒤", o.revokeIn)
		go func() {
			select {
			case <-ctx.Done():
			case <-time.After(o.revokeIn):
				t0 := time.Now()
				err := m.Revoke(warrantID)
				fmt.Fprintf(os.Stderr, "%s %s 취소 실행 (map 쓰기 %s) %v\n",
					stamp(time.Now()), paint(o.color, cMagenta, "‼"),
					time.Since(t0).Round(time.Microsecond), errOr(err))
			}
		}()
	}

	// 규칙이 가리키던 파일이 갈리면 그 규칙은 조용히 무효가 된다 (S4).
	watcher, err := policy.NewWatcher()
	if err != nil {
		return err
	}
	defer watcher.Close()
	_ = watcher.OnChange(func(id uint32) {
		fmt.Fprintf(os.Stderr, "%s %s 정책 %d 의 inode 가 바뀌었다 — 다시 컴파일한다\n",
			stamp(time.Now()), paint(o.color, cAmber, "⟳"), id)
		nc, err := policy.Compile(id, spec)
		if err != nil {
			fmt.Fprintln(os.Stderr, "  재컴파일 실패:", err)
			return
		}
		if err := nc.Apply(m); err != nil {
			fmt.Fprintln(os.Stderr, "  재적용 실패:", err)
			return
		}
		for _, src := range nc.Sources {
			names[src.Ref] = src.Path
		}
		_ = watcher.Watch(nc)
	})
	_ = watcher.Watch(compiled)

	c, err := ringbuf.Open(pinDir)
	if err != nil {
		return err
	}
	defer c.Close()

	c.OnGap(func(g ringbuf.Gap) {
		fmt.Fprintf(os.Stderr, "%s %s 감사 유실 %d건 (%s)\n",
			stamp(time.Now()), paint(o.color, cMagenta, "‼"), g.DroppedCount, g.Cause)
	})

	// boot 기준 타임스탬프를 벽시계로 옮긴다. 커널은 CLOCK_BOOTTIME 만 안다.
	bootNs, err := bpfmap.BootNs()
	if err != nil {
		return err
	}
	bootWall := time.Now().Add(-time.Duration(bootNs))

	fmt.Fprintf(os.Stderr, "─── 수신 시작 (active=%v) ───\n", o.active)

	// LSM 훅과 kprobe 미러가 같은 사건을 각각 기록한다. 둘을 다 찍으면 감사가
	// 두 배가 되므로 기본은 LSM 것만 보여준다. 다만 미러의 존재 이유는
	// 「판정이 갈리는지」라서 버리지 않고 짝을 맞춰 비교한다.
	d := newDivergence()
	err = c.Run(ctx, func(r ringbuf.Record) {
		if msg := d.observe(r); msg != "" {
			fmt.Fprintf(os.Stderr, "%s %s %s\n",
				stamp(time.Now()), paint(o.color, cMagenta, "‼"), msg)
		}
		if !o.mirror && r.Origin == originKprobe {
			return
		}
		fmt.Fprintln(os.Stderr, line(r, bootWall, names, o.color, o.mirror))
	})
	if n := d.unpaired(); n > 0 {
		fmt.Fprintf(os.Stderr, "─── 짝 없는 기록 %d건 (미러가 안 붙는 훅이다) ───\n", n)
	}
	fmt.Fprintf(os.Stderr, "─── 종료 (유실 누적 %d건) ───\n", c.DroppedTotal())
	if err != nil && err != context.Canceled {
		return err
	}
	return nil
}

// ── 출력 ──────────────────────────────────────────────────────────

const (
	cReset   = "\033[0m"
	cRed     = "\033[31m"
	cGreen   = "\033[32m"
	cAmber   = "\033[33m"
	cGray    = "\033[90m"
	cMagenta = "\033[35m"
)

func line(r ringbuf.Record, bootWall time.Time, names map[bpfmap.FileRef]string, color, showOrigin bool) string {
	ts := bootWall.Add(time.Duration(r.BootTsNs))
	verdict := ringbuf.VerdictName(r.Verdict, r.Mode)

	mark, col := "✓", cGreen
	switch r.Verdict {
	case 1:
		mark, col = "✗", cRed
	case 2:
		mark, col = "⚠", cAmber
	}

	tail := ringbuf.TagSourceName(r.TagSource)
	if showOrigin {
		tail += " " + ringbuf.OriginName(r.Origin)
	}
	return fmt.Sprintf("%s %s %-9s %s %-28s %s %s",
		paint(color, cGray, stamp(ts)),
		paint(color, col, mark),
		ringbuf.HookName(r.Hook),
		padTo(paint(color, col, verdict), len(verdict), 9),
		target(r, names),
		who(r),
		paint(color, cGray, tail))
}

func target(r ringbuf.Record, names map[bpfmap.FileRef]string) string {
	name := func(f ringbuf.FileRef) string {
		k := bpfmap.FileRef{Dev: f.Dev, Ino: f.Ino}
		if n, ok := names[k]; ok {
			return n
		}
		if f.Ino == 0 {
			return "-"
		}
		return fmt.Sprintf("ino:%d", f.Ino)
	}

	if e, ok := r.Exec(); ok {
		s := name(e.File)
		if e.IMode&0o4000 != 0 {
			s += " (setuid)"
		}
		return s
	}
	if w, ok := r.Write(); ok {
		return name(w.File)
	}
	if i, ok := r.Inode(); ok {
		return fmt.Sprintf("%s in %s", ringbuf.OpName(i.Op), name(i.Dir))
	}
	if c, ok := r.Connect(); ok {
		if c.UnixPath != "" {
			return c.UnixPath
		}
		if c.Addr.IsValid() {
			return fmt.Sprintf("%s:%d", c.Addr, c.Port)
		}
		return "-"
	}
	if f, ok := r.Fork(); ok {
		return fmt.Sprintf("pid %d -> %d", f.ParentTGID, f.ChildTGID)
	}
	return "-"
}

func who(r ringbuf.Record) string {
	s := fmt.Sprintf("%s(%d)", r.Proc.Comm, r.Proc.PID)
	if r.Proc.UID != r.Proc.EUID {
		s += fmt.Sprintf(" uid%d→%d", r.Proc.UID, r.Proc.EUID)
	} else {
		s += fmt.Sprintf(" uid%d", r.Proc.UID)
	}
	return fmt.Sprintf("%-26s", s)
}

// padTo 는 ANSI 코드를 뺀 실제 글자수로 폭을 맞춘다.
func padTo(s string, visible, width int) string {
	if visible >= width {
		return s
	}
	return s + strings.Repeat(" ", width-visible)
}

func paint(on bool, c, s string) string {
	if !on {
		return s
	}
	return c + s + cReset
}

func stamp(t time.Time) string { return t.Format("[15:04:05.000]") }

// ── LSM ↔ kprobe 미러 대조 ────────────────────────────────────────
//
// 같은 (pid, hook, 대상) 사건이 두 경로로 한 번씩 온다. 먼저 온 쪽을 들고
// 있다가 다른 origin 이 오면 판정을 비교한다. 갈리면 그건 버그다 —
// 감사 모드에서 안 걸리던 게 강제 모드에서 막히는 상황이 여기서 드러난다.

const originKprobe = 2

type dupKey struct {
	pid  uint32
	hook uint16
	dev  uint32
	ino  uint64
}

type divergence struct {
	pending map[dupKey]uint8 // → 먼저 본 verdict
	origin  map[dupKey]uint8
}

func newDivergence() *divergence {
	return &divergence{pending: map[dupKey]uint8{}, origin: map[dupKey]uint8{}}
}

func (d *divergence) observe(r ringbuf.Record) string {
	k, ok := keyOf(r)
	if !ok {
		return ""
	}
	if prev, seen := d.pending[k]; seen && d.origin[k] != r.Origin {
		delete(d.pending, k)
		delete(d.origin, k)
		if prev != r.Verdict {
			return fmt.Sprintf("판정 불일치 %s pid=%d ino=%d — lsm 과 kprobe 가 다르다 (%s vs %s)",
				ringbuf.HookName(r.Hook), k.pid, k.ino,
				ringbuf.VerdictName(prev, r.Mode), ringbuf.VerdictName(r.Verdict, r.Mode))
		}
		return ""
	}
	// 무한정 쌓이면 안 된다. 미러가 없는 훅이 대부분이라 짝이 안 맞는 게 정상이다.
	if len(d.pending) > 4096 {
		d.pending = map[dupKey]uint8{}
		d.origin = map[dupKey]uint8{}
	}
	d.pending[k] = r.Verdict
	d.origin[k] = r.Origin
	return ""
}

func (d *divergence) unpaired() int { return len(d.pending) }

func keyOf(r ringbuf.Record) (dupKey, bool) {
	k := dupKey{pid: r.Proc.PID, hook: r.Hook}
	switch {
	case r.Hook == ringbuf.HookFileOpen:
		w, ok := r.Write()
		if !ok {
			return k, false
		}
		k.dev, k.ino = w.File.Dev, w.File.Ino
	case r.Hook == ringbuf.HookBprmCheckSecurity:
		e, ok := r.Exec()
		if !ok {
			return k, false
		}
		k.dev, k.ino = e.File.Dev, e.File.Ino
	default:
		return k, false // 미러가 붙은 훅은 아직 file_open 뿐이다
	}
	return k, true
}

// ── 자잘한 것 ─────────────────────────────────────────────────────

func parseMode(s string) (uint8, error) {
	switch strings.ToLower(s) {
	case "observe":
		return bpfmap.ModeObserve, nil
	case "dryrun":
		return bpfmap.ModeDryRun, nil
	case "enforce":
		return bpfmap.ModeEnforce, nil
	}
	return 0, fmt.Errorf("mode 는 observe · dryrun · enforce 중 하나다: %q", s)
}

func split(s string) []string {
	if s == "" {
		return nil
	}
	out := strings.Split(s, ",")
	for i := range out {
		out[i] = strings.TrimSpace(out[i])
	}
	return out
}

func logf(color bool, format string, a ...any) {
	fmt.Fprintln(os.Stderr, paint(color, cGray, fmt.Sprintf(format, a...)))
}

func errOr(err error) any {
	if err == nil {
		return ""
	}
	return err
}

func isTTY(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}
