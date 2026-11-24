package policy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func tmpFile(t *testing.T, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// 금지를 파일 inode 에 걸면 mv 후 재생성으로 뚫린다. 컴파일러가 막아야 한다 (§15).
func TestDenyOnFileIsRejected(t *testing.T) {
	dir := t.TempDir()
	f := tmpFile(t, dir, "secret.conf")

	_, err := Compile(7, Spec{WriteRules: []WriteRule{
		{Path: f, Effect: EffectDeny, Recursive: true},
	}})
	if !errors.Is(err, ErrDenyOnFile) {
		t.Fatalf("파일 금지를 받아들였다: %v", err)
	}

	// 같은 경로가 디렉터리면 통과해야 한다.
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Compile(7, Spec{WriteRules: []WriteRule{
		{Path: sub, Effect: EffectDeny, Recursive: true},
	}}); err != nil {
		t.Fatalf("디렉터리 금지가 거부됐다: %v", err)
	}
}

// effect 를 빠뜨린 규칙이 ALLOW 로 읽히면 안 된다.
func TestMissingEffectIsRejected(t *testing.T) {
	dir := t.TempDir()
	_, err := Compile(7, Spec{WriteRules: []WriteRule{{Path: dir}}})
	if !errors.Is(err, ErrNoEffect) {
		t.Fatalf("effect 없는 규칙을 받아들였다: %v", err)
	}
}

func TestRejectsBadInput(t *testing.T) {
	dir := t.TempDir()
	f := tmpFile(t, dir, "bin")

	if _, err := Compile(0, Spec{}); !errors.Is(err, ErrNoPolicyID) {
		t.Error("policy_id 0 을 받아들였다")
	}
	if _, err := Compile(7, Spec{ExecRules: []ExecRule{{Path: "relative/path"}}}); err == nil {
		t.Error("상대 경로를 받아들였다")
	}
	if _, err := Compile(7, Spec{ExecRules: []ExecRule{{Path: dir}}}); !errors.Is(err, ErrExecNotFile) {
		t.Error("디렉터리 실행 허용을 받아들였다")
	}
	if _, err := Compile(7, Spec{NetRules: []NetRule{{CIDR: "10.0.0.1"}}}); err == nil {
		t.Error("프리픽스 없는 CIDR 을 받아들였다")
	}
	if _, err := Compile(7, "not a spec"); err == nil {
		t.Error("Spec 아닌 것을 받아들였다")
	}
	_ = f
}

// /dev/null 쓰기가 막히면 nohup 같은 정상 프로그램이 죽는다.
// 정책이 안 적어도 들어가야 한다.
func TestDefaultAllowIsInjected(t *testing.T) {
	c, err := Compile(7, Spec{})
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.Stat("/dev/null")
	if err != nil {
		t.Skip("/dev/null 이 없는 환경")
	}
	_ = want

	found := false
	for _, s := range c.Sources {
		if s.Path == "/dev/null" && s.Kind == KindWrite {
			found = true
		}
	}
	if !found {
		t.Error("/dev/null 이 기본 허용에 안 들어갔다")
	}
	for _, w := range c.Write {
		if !w.Allow {
			continue
		}
		return // 허용 항목이 하나라도 있으면 됐다
	}
	t.Error("기본 허용이 하나도 안 들어갔다")
}

// 규칙 하나하나는 멀쩡한데 합치면 임의 코드 실행이 되는 조합.
func TestDangerousCombination(t *testing.T) {
	dir := t.TempDir()
	systemctl := tmpFile(t, dir, "systemctl")
	unitDir := filepath.Join(dir, "unit")
	if err := os.Mkdir(unitDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// 조합 판정은 경로 이름으로 한다. 실제 /etc/systemd/system 을 쓸 수 없으니
	// 규칙 표가 보는 경로를 그대로 준다 — 존재해야 하므로 심볼릭 링크로 만든다.
	link := filepath.Join(dir, "sysd")
	if err := os.Symlink(unitDir, link); err != nil {
		t.Fatal(err)
	}

	c, err := Compile(7, Spec{
		ExecRules:  []ExecRule{{Path: systemctl}},
		WriteRules: []WriteRule{{Path: unitDir, Effect: EffectAllow, Recursive: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	// 이 경로는 표에 없으므로 조합 경고는 안 뜬다. 표가 도는지만 확인한다.
	for _, w := range c.Warnings {
		if strings.Contains(w, "systemctl 실행 허용") {
			t.Error("표에 없는 경로에 경고가 떴다")
		}
	}

	// 표에 있는 경로가 실제로 있으면 경고가 떠야 한다.
	if _, err := os.Stat("/etc/cron.d"); err == nil {
		c2, err := Compile(7, Spec{
			WriteRules: []WriteRule{{Path: "/etc/cron.d", Effect: EffectAllow, Recursive: true}},
		})
		if err != nil {
			t.Fatal(err)
		}
		hit := false
		for _, w := range c2.Warnings {
			if strings.Contains(w, "cron") {
				hit = true
			}
		}
		if !hit {
			t.Errorf("cron 경고가 안 떴다: %v", c2.Warnings)
		}
	}
}

func TestSetuidExecWarns(t *testing.T) {
	dir := t.TempDir()
	p := tmpFile(t, dir, "esc")

	// os.Chmod 는 유닉스 8진수가 아니라 os.FileMode 를 받는다. 거기서 setuid 는
	// bit 23(os.ModeSetuid) 이고 0o4000(bit 11) 이 아니다 — 0o4755 를 주면
	// 조용히 0o755 만 적용된다.
	//
	// 그래서 이 테스트는 쓰인 이래 한 번도 안 돌았다. 아래 가드가 걸려서
	// "파일시스템이 setuid 를 무시한다" 는 **틀린 사유**로 건너뛰었고, 그 문장
	// 때문에 /tmp 마운트를 들여다보게 됐다 (2026-11-06). SKIP 이 거짓말을 하면
	// 실패보다 나쁘다.
	if err := os.Chmod(p, 0o755|os.ModeSetuid); err != nil {
		t.Skipf("setuid 비트를 못 세운다: %v", err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode()&os.ModeSetuid == 0 {
		// 여기까지 와서 비어 있으면 그때는 진짜 파일시스템이 뗀 것이다.
		t.Skipf("파일시스템이 setuid 를 뗀다 (%s, mode=%v)", dir, st.Mode())
	}

	c, err := Compile(7, Spec{ExecRules: []ExecRule{{Path: p}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range c.Warnings {
		if strings.Contains(w, "setuid") {
			return
		}
	}
	t.Errorf("setuid 경고가 안 떴다: %v", c.Warnings)
}

func TestNoNetRulesWarns(t *testing.T) {
	c, err := Compile(7, Spec{})
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range c.Warnings {
		if strings.Contains(w, "아웃바운드") {
			return
		}
	}
	t.Errorf("아웃바운드 전면 차단 경고가 안 떴다: %v", c.Warnings)
}

// 감시는 규칙이 가리키던 파일이 사라지는 것은 잡는다.
func TestWatcherSeesPathGone(t *testing.T) {
	dir := t.TempDir()
	p := tmpFile(t, dir, "bin")

	c, err := Compile(7, Spec{ExecRules: []ExecRule{{Path: p}}})
	if err != nil {
		t.Fatal(err)
	}

	w, err := NewWatcherInterval(20 * time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	ch := make(chan uint32, 4)
	_ = w.OnChange(func(id uint32) {
		select {
		case ch <- id:
		default:
		}
	})
	if err := w.Watch(c); err != nil {
		t.Fatal(err)
	}

	// 가만히 두면 아무 일도 없어야 한다.
	select {
	case id := <-ch:
		t.Fatalf("안 바뀌었는데 변경으로 봤다: %d", id)
	case <-time.After(100 * time.Millisecond):
	}

	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	select {
	case id := <-ch:
		if id != 7 {
			t.Errorf("policy id=%d", id)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("파일이 사라졌는데 못 잡았다")
	}
}

// 알려진 한계를 고정한다.
//
// ext4 는 파일을 지우면 inode 번호를 즉시 재사용한다. 지우고 같은 자리에 다른
// 파일을 만들면 번호가 그대로라 (dev, ino) 만 보는 감시는 「안 바뀌었다」로 본다.
// 실행 허용이 다른 내용에 상속되는 경로가 바로 이것이다.
//
// 식별자에 i_generation 이 들어가면 이 테스트가 먼저 깨진다 — 그때 기대값을
// 뒤집고 TestWatcherSeesInodeReuse 로 이름을 바꾸면 된다.
func TestWatcherMissesInodeReuse(t *testing.T) {
	dir := t.TempDir()
	p := tmpFile(t, dir, "bin")

	before, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	tmpFile(t, dir, "bin")
	after, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if !sameInode(before, after) {
		t.Skip("이 파일시스템은 inode 번호를 재사용하지 않는다 (tmpfs 등)")
	}

	// 번호가 재사용됐다. 내용이 완전히 다른데도 감시는 변화를 못 본다.
	c, err := Compile(7, Spec{ExecRules: []ExecRule{{Path: p}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("완전히 다른 내용"), 0o755); err != nil {
		t.Fatal(err)
	}

	w := &Watcher{watched: map[uint32][]Source{7: c.Sources}}
	if got := w.changed(); len(got) != 0 {
		t.Logf("한계가 해소됐다 — 감시가 inode 재사용을 잡는다: %v", got)
		t.Log("TestWatcherSeesInodeReuse 로 바꾸고 기대값을 뒤집을 것")
		t.Fail()
	}
}

func sameInode(a, b os.FileInfo) bool {
	sa, ok1 := a.Sys().(*syscall.Stat_t)
	sb, ok2 := b.Sys().(*syscall.Stat_t)
	return ok1 && ok2 && sa.Ino == sb.Ino
}

func TestUnderRespectsBoundary(t *testing.T) {
	if under("/etc/cron.daily", []string{"/etc/cron"}) {
		t.Error("/etc/cron.daily 가 /etc/cron 아래로 잡혔다")
	}
	if !under("/etc/cron.d/job", []string{"/etc/cron.d"}) {
		t.Error("실제 하위 경로를 못 잡았다")
	}
	if !under("/etc/cron.d", []string{"/etc/cron.d"}) {
		t.Error("같은 경로를 못 잡았다")
	}
}

// 실행 허용 바이너리가 쓰기 허용 디렉터리 안에 있으면 그 파일을 갈아치울 수 있다.
// inode 번호가 재사용되므로 규칙은 그대로 맞고 실행되는 건 다른 바이너리다.
func TestExecUnderWritableDirWarns(t *testing.T) {
	dir := t.TempDir()
	bin := tmpFile(t, dir, "deploy")

	c, err := Compile(7, Spec{
		ExecRules:  []ExecRule{{Path: bin}},
		WriteRules: []WriteRule{{Path: dir, Effect: EffectAllow, Recursive: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range c.Warnings {
		if strings.Contains(w, "갈아치우면") {
			return
		}
	}
	t.Errorf("경고가 안 떴다: %v", c.Warnings)
}

// 쓰기 허용 밖에 있으면 경고가 뜨면 안 된다.
func TestExecOutsideWritableDirNoWarn(t *testing.T) {
	binDir := t.TempDir()
	bin := tmpFile(t, binDir, "deploy")
	dataDir := t.TempDir()

	c, err := Compile(7, Spec{
		ExecRules:  []ExecRule{{Path: bin}},
		WriteRules: []WriteRule{{Path: dataDir, Effect: EffectAllow, Recursive: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range c.Warnings {
		if strings.Contains(w, "갈아치우면") {
			t.Errorf("관계없는 디렉터리에 경고가 떴다: %s", w)
		}
	}
}

// os.Chmod 의 8진수 함정을 못 박아 둔다.
//
// 누가 TestSetuidExecWarns 를 0o4755 로 되돌리면 그 테스트는 실패가 아니라
// **SKIP** 으로 조용히 사라진다. 초록은 그대로라 아무도 안 본다. 그래서 전제
// 자체를 여기서 따로 센다 — 파일시스템도 커널도 안 타는 순수 비트 검사다.
func TestOctalSetuidIsNotFileModeSetuid(t *testing.T) {
	if os.FileMode(0o4755)&os.ModeSetuid != 0 {
		t.Error("0o4755 에 ModeSetuid 가 들어 있다 — Go 의 FileMode 의미가 바뀌었다")
	}
	if (0o755|os.ModeSetuid)&os.ModeSetuid == 0 {
		t.Error("0o755|os.ModeSetuid 에 setuid 가 없다")
	}
	if (0o755 | os.ModeSetuid).Perm() != 0o755 {
		t.Error("권한 비트가 어긋난다")
	}
}
