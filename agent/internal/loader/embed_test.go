package loader

import (
	"bytes"
	"debug/elf"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/cilium/ebpf"

	bpfobj "github.com/session-warrant/session-warrant/agent/bpf"
)

// sourceObject 는 bpf/ 가 방금 컴파일한 .o 다. clang 이 있는 기계에만 있다.
const sourceObject = "../../../bpf/warrant.bpf.o"

// 자기보호는 하나라도 빠지면 나머지가 무의미하다 (§16). 임베드된 쪽에서 그게
// 빠진 걸 노드에서 로드할 때가 아니라 여기서 잡는다.
var selfProtectSections = []string{
	"lsm/bpf",
	"lsm/kernel_module_request",
	"lsm/ptrace_access_check",
	"lsm/sb_umount",
	"lsm/task_kill",
}

func embeddedSpec(t *testing.T) *ebpf.CollectionSpec {
	t.Helper()
	if len(bpfobj.Object) == 0 {
		t.Fatal("임베드된 오브젝트가 비었다 — make -C agent bpf")
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfobj.Object))
	if err != nil {
		t.Fatalf("임베드된 오브젝트를 못 읽는다: %v", err)
	}
	return spec
}

// 커널이 없어도 할 수 있는 검사다 — ELF 를 파싱하는 것뿐이고 root 도 필요 없다.
func TestEmbeddedObjectParses(t *testing.T) {
	spec := embeddedSpec(t)
	if len(spec.Programs) == 0 {
		t.Fatal("프로그램이 0개다")
	}
	if len(spec.Maps) == 0 {
		t.Fatal("맵이 0개다")
	}
	for name, ps := range spec.Programs {
		if len(ps.Instructions) == 0 {
			t.Errorf("%s: 명령이 비었다", name)
		}
	}
	t.Logf("프로그램 %d · 맵 %d · %d바이트", len(spec.Programs), len(spec.Maps), len(bpfobj.Object))
}

// CO-RE 는 .BTF 로 돈다. llvm-strip 을 너무 세게 걸면(-s, --strip-all) 여기가
// 사라지고, 그러면 노드에서 로드가 실패한다 — 빌드는 아무 말도 안 한다.
// make -C agent bpf 는 -g(DWARF 만) 를 쓴다.
func TestEmbeddedObjectKeepsBTF(t *testing.T) {
	f, err := elf.NewFile(bytes.NewReader(bpfobj.Object))
	if err != nil {
		t.Fatalf("ELF 파싱: %v", err)
	}
	defer f.Close()

	for _, want := range []string{".BTF", ".BTF.ext"} {
		if f.Section(want) == nil {
			t.Errorf("%s 섹션이 없다 — strip 을 너무 세게 걸었다. CO-RE 가 안 된다", want)
		}
	}
}

func TestEmbeddedHasSelfProtect(t *testing.T) {
	have := make(map[string]bool)
	for _, ps := range embeddedSpec(t).Programs {
		have[ps.SectionName] = true
	}
	for _, want := range selfProtectSections {
		if !have[want] {
			t.Errorf("자기보호 훅 %s 이 임베드된 오브젝트에 없다 (§16)", want)
		}
	}
}

// 임베드된 .o 가 낡았는지 본다.
//
// 훅을 새로 붙이고 agent/bpf/ 로 들여오는 걸 잊으면, 테스트는 전부 초록인데
// warrantd 는 훅 하나 적게 올린다. S5 에서 낡은 바이너리를 사흘 돌린 적이
// 있다 — 그래서 사람이 눈치채야 하는 상태로 두지 않는다.
//
// 바이트로 비교하지 않는다. clang 버전 · vmlinux.h 가 다르면 같은 C 소스도 다른
// 바이트가 나오는데 그건 드리프트가 아니다. 프로그램과 맵의 목록만 본다.
func TestEmbeddedMatchesSource(t *testing.T) {
	if _, err := os.Stat(sourceObject); err != nil {
		t.Skipf("%s 이 없다 — clang 있는 기계에서만 하는 검사다", sourceObject)
	}
	src, err := ebpf.LoadCollectionSpec(sourceObject)
	if err != nil {
		t.Fatalf("%s: %v", sourceObject, err)
	}
	emb := embeddedSpec(t)

	if got, want := names(emb.Programs), names(src.Programs); got != want {
		t.Errorf("프로그램 목록이 다르다 — make -C agent bpf 를 다시 돌려라\n임베드: %s\nbpf/  : %s", got, want)
	}
	if got, want := mapNames(emb.Maps), mapNames(src.Maps); got != want {
		t.Errorf("맵 목록이 다르다 — make -C agent bpf 를 다시 돌려라\n임베드: %s\nbpf/  : %s", got, want)
	}
}

func names(progs map[string]*ebpf.ProgramSpec) string {
	out := make([]string, 0, len(progs))
	for _, ps := range progs {
		out = append(out, ps.SectionName)
	}
	sort.Strings(out)
	return strings.Join(out, " ")
}

func mapNames(maps map[string]*ebpf.MapSpec) string {
	out := make([]string, 0, len(maps))
	for _, ms := range maps {
		if strings.HasPrefix(ms.Name, ".") {
			continue // .rodata 같은 내부 맵은 세지 않는다
		}
		out = append(out, ms.Name)
	}
	sort.Strings(out)
	return strings.Join(out, " ")
}
