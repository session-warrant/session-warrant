// Package policy 는 경로를 (dev, ino) 로 컴파일한다. 이 변환은 여기서만 한다.
package policy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/session-warrant/session-warrant/agent/internal/bpfmap"
)

// Effect 는 proto WriteRule.Effect 와 값이 같다.
// 0 은 컴파일러가 거부한다 — 빠뜨린 DENY 가 ALLOW 로 읽히면 안 된다.
type Effect uint8

const (
	EffectUnspecified Effect = 0
	EffectAllow       Effect = 1
	EffectDeny        Effect = 2
)

// Kind 는 규칙의 종류다. Source 가 어느 맵으로 갔는지 가른다.
type Kind uint8

const (
	KindExec Kind = iota
	KindWrite
	KindRead
)

// Spec 은 proto Policy 의 Go 대응물이다.
// internal/pb 생성물이 들어오면 Compile 이 그것도 받게 한다 — 그래서 인자가 any 다.
type Spec struct {
	Name           string
	ExecRules      []ExecRule
	WriteRules     []WriteRule
	NetRules       []NetRule
	ReadWatchPaths []string
	InspectUDP     bool
}

type ExecRule struct {
	Path string
}

type WriteRule struct {
	Path      string
	Recursive bool
	Effect    Effect
}

type NetRule struct {
	CIDR  string
	Port  uint16
	Proto uint8
}

type Compiled struct {
	PolicyID uint32
	Exec     []bpfmap.FileRef
	Write    []WriteEntry
	Net      []NetEntry
	Read     []bpfmap.FileRef // 비어 있으면 BPF 가 읽기 경로를 아예 보지 않는다

	// Sources 는 컴파일에 쓴 경로와 그때의 inode 다.
	// Watcher 가 이걸 다시 stat 해서 바뀐 것을 알아낸다.
	Sources []Source

	// Warnings 는 막지는 않지만 사람이 봐야 하는 것들이다.
	// 규칙 하나하나는 멀쩡한데 조합이 구멍인 경우가 여기 걸린다.
	Warnings []string
}

type Source struct {
	Path string
	Ref  bpfmap.FileRef
	Kind Kind
}

type WriteEntry struct {
	Ref       bpfmap.FileRef
	Allow     bool
	Recursive bool
}

type NetEntry struct {
	CIDR  string
	Port  uint16
	Proto uint8
}

// DefaultAllowWrite 는 모든 정책에 강제로 들어가는 쓰기 허용이다.
//
// 이게 없으면 정상 프로그램이 죽는다. nohup 은 /dev/null 을 쓰기로 못 열어서
// 바로 실패했고, 데몬화하는 프로그램은 거의 전부 같은 일을 한다.
// 정책 작성자가 빠뜨릴 수 있는 것이지 작성자가 정할 것이 아니다.
//
// 여기 있는 것들도 DAC 는 여전히 지킨다 — LSM 은 제한을 더할 뿐 풀지 못한다.
var DefaultAllowWrite = []string{
	"/dev/null",
	"/dev/zero",
	"/dev/full",
	"/dev/random",
	"/dev/urandom",
	"/dev/tty",
	"/dev/pts", // 터미널. 디렉터리라 재귀로 들어간다
}

// DefaultDenyWrite 는 자기보호 6종의 여섯 번째다.
// 나머지 다섯은 LSM 훅이고 이것만 규칙이다 — 영장 세션이 warrantd 자기 상태를
// 고치지 못하게 한다 (§16).
//
// 금지는 디렉터리여야 한다. 파일 inode 로 걸면 mv 후 재생성으로 뚫린다 (§15).
// 없는 경로는 건너뛴다 — 개발 기계에는 warrantd 가 안 깔려 있다.
var DefaultDenyWrite = []string{
	"/var/lib/warrantd",
	"/run/warrantd",
	"/etc/warrantd",
}

var (
	ErrNoPolicyID  = errors.New("policy_id 가 0 이다. 정책마다 고유해야 한다")
	ErrDenyOnFile  = errors.New("금지 규칙이 파일이다. 디렉터리여야 한다")
	ErrNoEffect    = errors.New("쓰기 규칙에 effect 가 없다")
	ErrRelPath     = errors.New("절대 경로여야 한다")
	ErrExecNotFile = errors.New("실행 허용은 일반 파일이어야 한다")
)

// Compile 은 금지 규칙이 파일 inode 로 컴파일되면 거부한다. 금지는 디렉터리여야 한다.
func Compile(policyID uint32, spec any) (*Compiled, error) {
	var s *Spec
	switch v := spec.(type) {
	case *Spec:
		s = v
	case Spec:
		s = &v
	default:
		return nil, fmt.Errorf("policy.Spec 이어야 한다: %T", spec)
	}
	if policyID == 0 {
		return nil, ErrNoPolicyID
	}

	c := &Compiled{PolicyID: policyID}

	for _, r := range s.ExecRules {
		st, err := os.Stat(r.Path)
		if err != nil {
			return nil, fmt.Errorf("실행 허용 %s: %w", r.Path, err)
		}
		if !st.Mode().IsRegular() {
			return nil, fmt.Errorf("실행 허용 %s: %w", r.Path, ErrExecNotFile)
		}
		ref, err := c.resolve(r.Path, KindExec)
		if err != nil {
			return nil, err
		}
		if st.Mode()&os.ModeSetuid != 0 {
			c.warn("%s 는 setuid 다 — 실행을 허용하면 영장 밖 권한으로 올라갈 수 있다", r.Path)
		}
		c.Exec = append(c.Exec, ref)
	}

	// 기본값을 먼저 깐다. 정책이 같은 경로를 다시 쓰면 뒤에 들어간 쪽이 이긴다 —
	// 기본값은 바닥을 깔아주는 것이지 정책을 이기는 것이 아니다.
	for _, p := range DefaultAllowWrite {
		if err := c.addWrite(p, true, true, true); err != nil {
			return nil, err
		}
	}
	for _, p := range DefaultDenyWrite {
		if err := c.addWrite(p, false, true, true); err != nil {
			return nil, err
		}
	}

	for _, r := range s.WriteRules {
		switch r.Effect {
		case EffectAllow:
			if err := c.addWrite(r.Path, true, r.Recursive, false); err != nil {
				return nil, err
			}
		case EffectDeny:
			if err := c.addWrite(r.Path, false, r.Recursive, false); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("쓰기 규칙 %s: %w", r.Path, ErrNoEffect)
		}
	}

	for _, r := range s.NetRules {
		if err := checkCIDR(r.CIDR); err != nil {
			return nil, err
		}
		c.Net = append(c.Net, NetEntry{CIDR: r.CIDR, Port: r.Port, Proto: r.Proto})
	}
	if len(s.NetRules) == 0 {
		c.warn("네트워크 규칙이 없다 — 아웃바운드가 전면 차단된다 (§15)")
	}

	for _, p := range s.ReadWatchPaths {
		ref, err := c.resolve(p, KindRead)
		if err != nil {
			return nil, err
		}
		c.Read = append(c.Read, ref)
	}

	c.checkCombinations(s)
	return c, nil
}

// Apply 는 컴파일된 정책을 커널 맵에 넣는다.
// 금지를 허용보다 먼저 넣는다 — 중간 상태에서 구멍이 생기면 안 된다.
func (c *Compiled) Apply(m *bpfmap.Maps) error {
	for _, w := range c.Write {
		if !w.Allow {
			if err := m.PutWriteRule(c.PolicyID, w.Ref, false, w.Recursive); err != nil {
				return err
			}
		}
	}
	for _, w := range c.Write {
		if w.Allow {
			if err := m.PutWriteRule(c.PolicyID, w.Ref, true, w.Recursive); err != nil {
				return err
			}
		}
	}
	for _, e := range c.Exec {
		if err := m.PutExecRule(c.PolicyID, e); err != nil {
			return err
		}
	}
	for _, n := range c.Net {
		if err := m.PutNetRule(c.PolicyID, n.CIDR, n.Port, n.Proto); err != nil {
			return err
		}
	}
	return nil
}

// ── 내부 ──────────────────────────────────────────────────────────

func (c *Compiled) warn(format string, a ...any) {
	c.Warnings = append(c.Warnings, fmt.Sprintf(format, a...))
}

func (c *Compiled) resolve(path string, kind Kind) (bpfmap.FileRef, error) {
	if !filepath.IsAbs(path) {
		return bpfmap.FileRef{}, fmt.Errorf("%s: %w", path, ErrRelPath)
	}
	ref, err := bpfmap.FileRefOf(path)
	if err != nil {
		return bpfmap.FileRef{}, err
	}
	c.Sources = append(c.Sources, Source{Path: path, Ref: ref, Kind: kind})
	return ref, nil
}

// addWrite 의 optional 은 「없으면 건너뛴다」 다. 기본 목록에만 쓴다 —
// 컨테이너나 개발 기계에는 없는 경로가 있다.
func (c *Compiled) addWrite(path string, allow, recursive, optional bool) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%s: %w", path, ErrRelPath)
	}
	st, err := os.Stat(path)
	if err != nil {
		if optional && os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("쓰기 규칙 %s: %w", path, err)
	}

	// 금지를 파일 inode 에 걸면 mv 후 재생성으로 뚫린다. 반드시 디렉터리여야 한다 (§15).
	if !allow && !st.IsDir() {
		return fmt.Errorf("쓰기 금지 %s: %w", path, ErrDenyOnFile)
	}

	ref, err := c.resolve(path, KindWrite)
	if err != nil {
		return err
	}
	c.Write = append(c.Write, WriteEntry{Ref: ref, Allow: allow, Recursive: recursive})
	return nil
}

func checkCIDR(cidr string) error {
	if !strings.Contains(cidr, "/") {
		return fmt.Errorf("CIDR %q: 프리픽스 길이가 없다 (예: 10.0.0.0/8)", cidr)
	}
	return nil
}

// ── 위험한 조합 ───────────────────────────────────────────────────
//
// 규칙 하나하나는 멀쩡한데 둘을 같이 주면 임의 코드 실행이 되는 경우들이다.
// 정책을 눈으로 읽어서는 잘 안 보인다.

var comboRules = []struct {
	exec  []string // 실행 파일 이름
	write []string // 쓰기 허용 경로
	why   string
}{
	{
		[]string{"systemctl", "systemd-run"},
		[]string{"/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system", "/run/systemd/system"},
		"unit 파일을 쓰고 systemctl 로 띄우면 임의 코드 실행이다",
	},
	{
		[]string{"sudo"},
		[]string{"/etc/sudoers", "/etc/sudoers.d"},
		"sudoers 를 고치고 sudo 를 부르면 영장 밖 권한으로 올라간다",
	},
	{
		[]string{"mount", "umount"},
		[]string{"/etc/fstab"},
		"fstab 을 고치고 mount 하면 임의 경로를 덮어쓸 수 있다",
	},
}

// 실행 허용과 무관하게 위험한 쓰기.
// 다른 주체(cron · 로그인 셸 · 동적 로더)가 대신 실행해주기 때문이다.
var alwaysRisky = []struct {
	write []string
	why   string
}{
	{[]string{"/etc/ld.so.preload", "/etc/ld.so.conf", "/etc/ld.so.conf.d"},
		"동적 로더 설정이다 — 이후 실행되는 모든 프로세스에 코드가 끼어든다"},
	{[]string{"/etc/cron.d", "/etc/crontab", "/var/spool/cron", "/etc/cron.hourly", "/etc/cron.daily"},
		"cron 이 다음 주기에 대신 실행해준다. 실행 허용이 없어도 돈다"},
	{[]string{"/etc/profile", "/etc/profile.d", "/etc/bash.bashrc"},
		"다음 로그인 셸이 대신 실행해준다"},
	{[]string{"/etc/passwd", "/etc/shadow", "/etc/group"},
		"계정을 만들거나 비밀번호를 바꿀 수 있다"},
	{[]string{"/root/.ssh", "/etc/ssh"},
		"authorized_keys 를 넣으면 영장 밖 경로로 다시 들어올 수 있다"},
}

func (c *Compiled) checkCombinations(s *Spec) {
	var allowed []string
	for _, r := range s.WriteRules {
		if r.Effect == EffectAllow {
			allowed = append(allowed, filepath.Clean(r.Path))
		}
	}
	if len(allowed) == 0 {
		return
	}

	execNames := map[string]bool{}
	for _, r := range s.ExecRules {
		execNames[filepath.Base(r.Path)] = true
	}

	for _, combo := range comboRules {
		hit := ""
		for _, n := range combo.exec {
			if execNames[n] {
				hit = n
				break
			}
		}
		if hit == "" {
			continue
		}
		for _, w := range allowed {
			if under(w, combo.write) {
				c.warn("%s 실행 허용 + %s 쓰기 허용 — %s", hit, w, combo.why)
			}
		}
	}

	for _, r := range alwaysRisky {
		for _, w := range allowed {
			if under(w, r.write) {
				c.warn("%s 쓰기 허용 — %s", w, r.why)
			}
		}
	}

	// 실행 허용된 바이너리가 쓰기 허용 디렉터리 안에 있으면, 그 파일을 갈아치워
	// 실행 허용을 다른 내용에 물려줄 수 있다.
	//
	// (dev, ino) 는 파일을 고유하게 식별하지 못한다 — ext4 는 파일을 지우면
	// inode 번호를 즉시 재사용하므로, 같은 자리에 다른 파일을 만들면 번호가
	// 그대로다. 규칙은 그대로 맞고 실행되는 건 다른 바이너리다.
	//
	// 근본 해결은 식별자에 i_generation 을 넣는 것이고 그건 공유 레이아웃을
	// 바꾼다. 여기서는 그 공격의 전제조건을 경고로 잡는다.
	for _, e := range s.ExecRules {
		for _, w := range allowed {
			if under(filepath.Clean(e.Path), []string{w}) {
				c.warn("%s 실행 허용 + 그 디렉터리(%s) 쓰기 허용 — "+
					"바이너리를 갈아치우면 실행 허용이 다른 내용에 상속된다", e.Path, w)
			}
		}
	}
}

// under 는 path 가 prefixes 중 하나와 같거나 그 아래인지 본다.
// 문자열 접두사로만 보면 /etc/cron.daily 가 /etc/cron 에 걸리므로 경계를 확인한다.
func under(path string, prefixes []string) bool {
	for _, p := range prefixes {
		if path == p || strings.HasPrefix(path, p+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// ── Watcher ───────────────────────────────────────────────────────

// Watcher 는 inode 가 바뀌면 다시 컴파일한다. 놓치면 정책이 조용히 무효가 된다 (S4).
//
// 지금은 주기적 재stat 이다. 기획서가 fanotify 를 지목했지만 그게 모든 변형을
// 잡는지는 S4 가 아직 안 돌았다 — 재stat 은 느린 대신 확실하고, S4 결과가
// 나오면 fanotify 로 바꾸면서 이 구현을 기준값으로 쓸 수 있다.
type Watcher struct {
	interval time.Duration

	mu       sync.Mutex
	watched  map[uint32][]Source
	onChange func(policyID uint32)

	stop chan struct{}
	done chan struct{}
	once sync.Once
}

// DefaultInterval 은 재stat 주기다. 정책이 바뀌는 빈도가 낮아 짧을 이유가 없다.
const DefaultInterval = 10 * time.Second

func NewWatcher() (*Watcher, error) { return NewWatcherInterval(DefaultInterval) }

func NewWatcherInterval(d time.Duration) (*Watcher, error) {
	if d <= 0 {
		return nil, errors.New("주기가 0 이하다")
	}
	w := &Watcher{
		interval: d,
		watched:  map[uint32][]Source{},
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	go w.loop()
	return w, nil
}

func (w *Watcher) Watch(c *Compiled) error {
	if c == nil || c.PolicyID == 0 {
		return ErrNoPolicyID
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.watched[c.PolicyID] = append([]Source(nil), c.Sources...)
	return nil
}

func (w *Watcher) Unwatch(policyID uint32) {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.watched, policyID)
}

func (w *Watcher) OnChange(f func(policyID uint32)) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.onChange = f
	return nil
}

func (w *Watcher) Close() error {
	w.once.Do(func() {
		close(w.stop)
		<-w.done
	})
	return nil
}

func (w *Watcher) loop() {
	defer close(w.done)
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		select {
		case <-w.stop:
			return
		case <-t.C:
			for _, id := range w.changed() {
				w.mu.Lock()
				f := w.onChange
				w.mu.Unlock()
				if f != nil {
					f(id)
				}
			}
		}
	}
}

// changed 는 inode 가 달라진 정책 id 를 돌려준다.
//
// 경로가 사라진 것도 변경이다 — 규칙이 가리키던 파일이 없어졌으면 그 규칙은
// 이미 무효다.
//
// 알려진 사각지대: ext4 는 파일을 지우면 inode 번호를 즉시 재사용한다.
// 지우고 같은 자리에 다른 파일을 만들면 번호가 그대로라 여기서 「안 바뀌었다」로
// 보인다. (dev, ino) 만으로는 원리적으로 구분할 수 없고 식별자에
// i_generation 이 들어가야 잡힌다. TestWatcherMissesInodeReuse 가 이 한계를
// 고정해 둔다 — 고쳐지면 그 테스트가 먼저 깨진다.
func (w *Watcher) changed() []uint32 {
	w.mu.Lock()
	snapshot := make(map[uint32][]Source, len(w.watched))
	for id, srcs := range w.watched {
		snapshot[id] = srcs
	}
	w.mu.Unlock()

	var out []uint32
	for id, srcs := range snapshot {
		for _, s := range srcs {
			now, err := bpfmap.FileRefOf(s.Path)
			if err != nil || now != s.Ref {
				out = append(out, id)
				break
			}
		}
	}
	return out
}
