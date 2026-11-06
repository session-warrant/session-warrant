package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 테스트가 /etc/shells 를 안 보게 갈아끼운다. 기계마다 내용이 달라서
// 진짜 파일을 쓰면 통과 여부가 기계에 달린 테스트가 된다.
func fakeShells(t *testing.T, lines string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "shells")
	if err := os.WriteFile(p, []byte(lines), 0o644); err != nil {
		t.Fatal(err)
	}
	orig := LoginShellsPath
	LoginShellsPath = p
	t.Cleanup(func() { LoginShellsPath = orig })
	return dir
}

func TestLoginShellsFiltersJunk(t *testing.T) {
	dir := t.TempDir()
	good := tmpFile(t, dir, "mysh")
	sub := filepath.Join(dir, "adir")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}

	fakeShells(t, strings.Join([]string{
		"# 주석",
		"",
		"   ",
		good,
		good,                       // 중복
		filepath.Join(dir, "없는파일"), // 없는 경로
		sub,                        // 디렉터리
		"relative/path",            // 상대 경로
	}, "\n"))

	got := LoginShells()
	if len(got) != 1 || got[0] != good {
		t.Fatalf("got=%v, 기대 [%s]", got, good)
	}
}

// 파일이 없으면 빈 목록이 아니라 대체 목록으로 간다 —
// 빈 목록이면 강제 모드에서 세션이 아예 안 뜬다.
func TestLoginShellsFallsBack(t *testing.T) {
	dir := t.TempDir()
	alt := tmpFile(t, dir, "fallbacksh")

	orig, origFb := LoginShellsPath, FallbackLoginShells
	LoginShellsPath = filepath.Join(dir, "없는파일")
	FallbackLoginShells = []string{alt}
	defer func() { LoginShellsPath, FallbackLoginShells = orig, origFb }()

	got := LoginShells()
	if len(got) != 1 || got[0] != alt {
		t.Fatalf("got=%v, 기대 [%s]", got, alt)
	}

	// 내용이 전부 쓸모없을 때도 같다.
	LoginShellsPath = filepath.Join(dir, "shells2")
	if err := os.WriteFile(LoginShellsPath, []byte("# 주석뿐\n\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := LoginShells(); len(got) != 1 || got[0] != alt {
		t.Fatalf("내용이 비었을 때 got=%v", got)
	}
}

// sshd 는 세션 scope 안에서 로그인 셸을 exec 한다. 그게 허용 목록에 없으면
// 강제 모드에서 세션 자체가 안 뜬다 (S5). 정책이 한 줄도 안 적어도 들어가야 한다.
func TestLoginShellAllowedWithoutAnyExecRule(t *testing.T) {
	dir := t.TempDir()
	sh := tmpFile(t, dir, "bash")
	fakeShells(t, sh)

	c, err := Compile(7, Spec{Name: "빈 정책"})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Exec) != 1 {
		t.Fatalf("실행 허용 %d개, 기대 1개: %+v", len(c.Exec), c.Exec)
	}
	var found bool
	for _, s := range c.Sources {
		if s.Kind == KindExec && s.Path == sh {
			found = true
		}
	}
	if !found {
		t.Errorf("Sources 에 셸이 없다 — Watcher 가 못 본다")
	}
}

// 같은 셸을 정책이 또 적어도 한 번만 들어가야 한다.
// 중복되면 Sources 가 늘어나 Watcher 가 같은 파일을 두 번 센다.
func TestExecDedupes(t *testing.T) {
	dir := t.TempDir()
	sh := tmpFile(t, dir, "bash")
	fakeShells(t, sh)

	// 심볼릭 링크로 경로만 다르게 해도 같은 inode 다.
	link := filepath.Join(dir, "sh")
	if err := os.Symlink(sh, link); err != nil {
		t.Fatal(err)
	}

	c, err := Compile(7, Spec{ExecRules: []ExecRule{{Path: sh}, {Path: link}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Exec) != 1 {
		t.Fatalf("실행 허용 %d개, 기대 1개 (기본 + 명시 + 링크가 전부 같은 파일)", len(c.Exec))
	}
	n := 0
	for _, s := range c.Sources {
		if s.Kind == KindExec {
			n++
		}
	}
	if n != 1 {
		t.Errorf("Sources 의 exec 항목 %d개, 기대 1개", n)
	}
}

// 비대화형 영장을 위해 끌 수 있어야 한다. 끄면 경고가 남아야 한다 —
// 세션이 안 뜨는 건 조용히 일어나면 안 된다.
func TestNoDefaultExecTurnsItOff(t *testing.T) {
	dir := t.TempDir()
	sh := tmpFile(t, dir, "bash")
	fakeShells(t, sh)

	c, err := Compile(7, Spec{NoDefaultExec: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Exec) != 0 {
		t.Fatalf("껐는데 실행 허용이 %d개 들어갔다", len(c.Exec))
	}
	if !hasWarn(c, "로그인 셸 기본 허용을 껐다") {
		t.Errorf("경고가 없다: %v", c.Warnings)
	}
}

// 셸을 하나도 못 찾으면 조용히 넘어가면 안 된다.
func TestNoLoginShellWarns(t *testing.T) {
	dir := t.TempDir()
	orig, origFb := LoginShellsPath, FallbackLoginShells
	LoginShellsPath = filepath.Join(dir, "없는파일")
	FallbackLoginShells = []string{filepath.Join(dir, "이것도없다")}
	defer func() { LoginShellsPath, FallbackLoginShells = orig, origFb }()

	c, err := Compile(7, Spec{})
	if err != nil {
		t.Fatal(err)
	}
	if !hasWarn(c, "로그인 셸을 하나도 못 찾았다") {
		t.Errorf("경고가 없다: %v", c.Warnings)
	}
}

func hasWarn(c *Compiled, sub string) bool {
	for _, w := range c.Warnings {
		if strings.Contains(w, sub) {
			return true
		}
	}
	return false
}
