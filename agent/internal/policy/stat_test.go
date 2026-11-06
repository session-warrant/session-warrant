package policy

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/session-warrant/session-warrant/agent/internal/bpfmap"
)

// 맵에 넣는 ref 와 Watcher 가 감시하는 ref 가 같아야 한다.
//
// 예전에는 addExec 이 같은 경로를 세 번 stat 했다 — 검사용 · 맵에 넣을 것 ·
// Sources 에 넣을 것. 뒤 둘이 갈리면 커널이 든 inode 는 아무도 안 보고
// 감시자는 커널이 모르는 inode 를 본다. S4 가 잡으려는 상황에서 감시가
// 엉뚱한 데를 보게 된다.
func TestSourcesRefMatchesCompiledRef(t *testing.T) {
	dir := t.TempDir()
	bin := tmpFile(t, dir, "tool")
	sub := filepath.Join(dir, "data")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}

	c, err := Compile(7, Spec{
		NoDefaultExec: true,
		ExecRules:     []ExecRule{{Path: bin}},
		WriteRules: []WriteRule{
			{Path: sub, Effect: EffectAllow, Recursive: true},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	byPath := map[string]bpfmap.FileRef{}
	for _, s := range c.Sources {
		byPath[s.Path] = s.Ref
	}

	if len(c.Exec) != 1 {
		t.Fatalf("Exec %d개: %+v", len(c.Exec), c.Exec)
	}
	if got, ok := byPath[bin]; !ok {
		t.Errorf("%s 가 Sources 에 없다 — Watcher 가 감시하지 않는다", bin)
	} else if got != c.Exec[0] {
		t.Errorf("exec ref 가 Sources 와 다르다: 맵 %+v · 감시 %+v", c.Exec[0], got)
	}

	var found bool
	for _, w := range c.Write {
		if got, ok := byPath[sub]; ok && got == w.Ref {
			found = true
		}
	}
	if !found {
		t.Errorf("write ref 가 Sources 와 다르거나 없다: write=%+v sources=%+v", c.Write, c.Sources)
	}
}

// 같은 경로를 두 번 넣어도 Sources 에 하나만 있어야 한다.
// 중복이 쌓이면 Watcher 가 같은 것을 두 번 센다.
func TestExecSourcesHaveNoDuplicate(t *testing.T) {
	dir := t.TempDir()
	bin := tmpFile(t, dir, "tool")
	link := filepath.Join(dir, "tool-link")
	if err := os.Symlink(bin, link); err != nil {
		t.Fatal(err)
	}

	c, err := Compile(7, Spec{NoDefaultExec: true, ExecRules: []ExecRule{{Path: bin}, {Path: link}}})
	if err != nil {
		t.Fatal(err)
	}
	// 심볼릭 링크를 따라가면 같은 inode 다 — 두 번 들어가면 안 된다.
	if len(c.Exec) != 1 {
		t.Errorf("Exec %d개, 기대 1개 (같은 inode): %+v", len(c.Exec), c.Exec)
	}
	n := 0
	for _, s := range c.Sources {
		if s.Kind == KindExec {
			n++
		}
	}
	if n != 1 {
		t.Errorf("Sources 의 exec 항목 %d개, 기대 1개 — Watcher 가 두 번 센다", n)
	}
}

// FileRefFromStat 과 FileRefOf 가 같은 값을 줘야 한다. 둘이 갈리면 한 번만
// stat 하도록 바꾼 자리에서 조용히 다른 inode 가 들어간다.
func TestFileRefFromStatMatchesFileRefOf(t *testing.T) {
	dir := t.TempDir()
	p := tmpFile(t, dir, "x")

	want, err := bpfmap.FileRefOf(p)
	if err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Stat(p, &st); err != nil {
		t.Fatal(err)
	}
	if got := bpfmap.FileRefFromStat(&st); got != want {
		t.Errorf("FileRefFromStat=%+v · FileRefOf=%+v", got, want)
	}
	if want.Dev == 0 && want.Ino == 0 {
		t.Error("ref 가 비었다")
	}
}
