package policy

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// 맵 키가 (policy_id, dev, ino) 라, 같은 inode 에 허용과 금지를 같이 주면
// 뒤에 들어간 쪽이 앞엣것을 덮는다. 예전에는 그게 조용히 일어났다 —
// 정책을 쓴 사람은 금지를 걸었다고 믿는데 맵에는 허용이 들어가 있었다.
func TestWriteAllowDenyConflictIsRejected(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "data")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}

	_, err := Compile(7, Spec{
		NoDefaultExec: true,
		WriteRules: []WriteRule{
			{Path: sub, Effect: EffectAllow, Recursive: true},
			{Path: sub, Effect: EffectDeny, Recursive: true},
		},
	})
	if !errors.Is(err, ErrWriteConflict) {
		t.Fatalf("충돌을 거부해야 한다. err=%v", err)
	}
}

// 진짜 위험한 건 경로가 둘인 경우다. 사람 눈에는 다른 규칙인데 커널 맵에서는
// 같은 키라, 눈으로 읽어서는 충돌이 안 보인다.
func TestWriteConflictThroughSymlink(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "data")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "data-link")
	if err := os.Symlink(sub, link); err != nil {
		t.Fatal(err)
	}

	_, err := Compile(7, Spec{
		NoDefaultExec: true,
		WriteRules: []WriteRule{
			{Path: sub, Effect: EffectAllow, Recursive: true},
			{Path: link, Effect: EffectDeny, Recursive: true},
		},
	})
	if !errors.Is(err, ErrWriteConflict) {
		t.Fatalf("심볼릭 링크로 같은 inode 인 충돌을 거부해야 한다. err=%v", err)
	}
}

// 결과가 같으면 충돌이 아니다. 경로만 둘일 뿐이라 통과해야 하고,
// 맵과 Sources 에는 하나만 들어가야 한다 — 중복이 쌓이면 Watcher 가 두 번 센다.
func TestWriteDuplicateSameEffectIsKept(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "data")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "data-link")
	if err := os.Symlink(sub, link); err != nil {
		t.Fatal(err)
	}
	// 기본 허용(/dev/null 등)을 비워야 센 수가 이 테스트 것만 남는다.
	swapDefaults(t, nil, nil)

	c, err := Compile(7, Spec{
		NoDefaultExec: true,
		WriteRules: []WriteRule{
			{Path: sub, Effect: EffectAllow, Recursive: true},
			{Path: link, Effect: EffectAllow, Recursive: true},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	n := 0
	for _, w := range c.Write {
		if w.Allow {
			n++
		}
	}
	if n != 1 {
		t.Errorf("허용 항목 %d개, 기대 1개: %+v", n, c.Write)
	}
	k := 0
	for _, s := range c.Sources {
		if s.Kind == KindWrite {
			k++
		}
	}
	if k != 1 {
		t.Errorf("Sources 의 write 항목 %d개, 기대 1개 — Watcher 가 두 번 센다", k)
	}
}

// 기본 허용은 바닥을 깔아주는 것이다. 정책이 덮는 것이 설계이고,
// 충돌 검사를 넣으면서 이게 깨지면 안 된다.
func TestPolicyOverridesDefaultAllow(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "scratch")
	if err := os.Mkdir(base, 0o755); err != nil {
		t.Fatal(err)
	}
	swapDefaults(t, []string{base}, nil)

	c, err := Compile(7, Spec{
		NoDefaultExec: true,
		WriteRules:    []WriteRule{{Path: base, Effect: EffectDeny, Recursive: true}},
	})
	if err != nil {
		t.Fatalf("정책이 기본 허용을 덮는 건 설계대로 통과해야 한다. err=%v", err)
	}
	if len(c.Write) != 1 {
		t.Fatalf("Write %d개, 기대 1개 (덮어쓰기): %+v", len(c.Write), c.Write)
	}
	if c.Write[0].Allow {
		t.Errorf("정책의 금지가 이겨야 한다: %+v", c.Write[0])
	}
}

// 자기보호 금지는 제품이 넣는 것이고 영장이 못 연다 (§16).
// 하나라도 열리면 나머지 다섯이 무의미해진다.
func TestSelfProtectDenyCannotBeOverridden(t *testing.T) {
	dir := t.TempDir()
	guard := filepath.Join(dir, "warrantd")
	if err := os.Mkdir(guard, 0o755); err != nil {
		t.Fatal(err)
	}
	swapDefaults(t, nil, []string{guard})

	_, err := Compile(7, Spec{
		NoDefaultExec: true,
		WriteRules:    []WriteRule{{Path: guard, Effect: EffectAllow, Recursive: true}},
	})
	if !errors.Is(err, ErrSelfProtectOverride) {
		t.Fatalf("자기보호 경로를 여는 정책은 거부해야 한다. err=%v", err)
	}
}

// 경로를 바꿔 쓰면 못 보게 숨길 수 있는지 — 심볼릭 링크로도 막혀야 한다.
func TestSelfProtectOverrideThroughSymlinkIsRejected(t *testing.T) {
	dir := t.TempDir()
	guard := filepath.Join(dir, "warrantd")
	if err := os.Mkdir(guard, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "looks-harmless")
	if err := os.Symlink(guard, link); err != nil {
		t.Fatal(err)
	}
	swapDefaults(t, nil, []string{guard})

	_, err := Compile(7, Spec{
		NoDefaultExec: true,
		WriteRules:    []WriteRule{{Path: link, Effect: EffectAllow, Recursive: true}},
	})
	if !errors.Is(err, ErrSelfProtectOverride) {
		t.Fatalf("다른 이름으로 들어와도 거부해야 한다. err=%v", err)
	}
}

// swapDefaults 는 기본 목록을 테스트용으로 갈아끼운다.
//
// 진짜 기본값(/dev/null · /var/lib/warrantd ...)으로는 이걸 못 쟀다 —
// 자기보호 경로는 개발 기계에 없어서 optional 로 건너뛰어지고, 그러면
// 덮어쓸 대상 자체가 안 생긴다.
func swapDefaults(t *testing.T, allow, deny []string) {
	t.Helper()
	oldAllow, oldDeny := DefaultAllowWrite, DefaultDenyWrite
	DefaultAllowWrite, DefaultDenyWrite = allow, deny
	t.Cleanup(func() {
		DefaultAllowWrite, DefaultDenyWrite = oldAllow, oldDeny
	})
}
