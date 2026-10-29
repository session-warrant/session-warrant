// Package loader 는 BPF 오브젝트를 로드하고 bpffs 에 pin 하고 훅을 attach 한다.
package loader

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// DefaultObjectPath 는 컴파일된 BPF 오브젝트의 기본 위치다.
//
// 지금은 파일에서 읽는다. agent/bpf/ 에 bpf2go 생성물이 들어오면 임베드된 것을
// 쓰도록 바꾼다 — 그래야 빌드 머신에 clang 이 없어도 go build 가 선다.
var DefaultObjectPath = "bpf/warrant.bpf.o"

// linkSubdir 은 pin 디렉터리 안에서 링크를 두는 곳이다.
// 맵과 같은 곳에 두면 맵을 이름으로 훑는 쪽이 링크를 맵으로 착각한다.
const linkSubdir = "links"

type Loader struct {
	coll    *ebpf.Collection
	spec    *ebpf.CollectionSpec
	pinDir  string
	linkDir string

	links    map[string]link.Link // 프로그램 이름 → 링크
	attached []string             // SEC 이름. 사람이 읽는 용도

	// missing 은 안 붙은 감사 미러다 (SEC 이름 + 이유).
	// 미러는 판정하지 않고 LSM 판정과 대조만 하므로, 못 붙어도 집행은
	// 계속하는 게 맞다 — 다만 조용히 넘어가면 「대조했는데 안 갈렸다」와
	// 「대조를 아예 안 했다」가 구분되지 않는다.
	missing []string
}

// Load 는 이미 pin 된 맵이 있으면 새로 만들지 않고 재사용한다.
func Load(pinDir string) (*Loader, error) { return LoadObject(DefaultObjectPath, pinDir) }

// LoadObject 는 오브젝트 경로를 직접 받는다.
//
// 맵은 pin 이 있으면 그걸 열고 없으면 만들어서 pin 한다. warrantd 가 재시작해도
// 맵이 살아 있어야 태깅 공백이 안 생긴다 — 그 사이에 로그인한 세션은 태그를
// 못 받는다.
func LoadObject(objPath, pinDir string) (*Loader, error) {
	if err := os.MkdirAll(pinDir, 0o700); err != nil {
		return nil, fmt.Errorf("pin 디렉터리 %s: %w", pinDir, err)
	}
	linkDir := filepath.Join(pinDir, linkSubdir)
	if err := os.MkdirAll(linkDir, 0o700); err != nil {
		return nil, fmt.Errorf("링크 디렉터리 %s: %w", linkDir, err)
	}

	// 「없으면 만들어서 pin」 은 두 인스턴스가 겹치면 깨진다. 둘 다 pin 이
	// 없는 것을 보고 각자 만든 뒤, 하나가 먼저 pin 하면 나머지가 EEXIST 로
	// 죽는다. warrantd 가 재시작될 때 이전 인스턴스가 아직 내려가는 중이면
	// 새 인스턴스가 못 뜬다는 뜻이다.
	//
	// 실측: 두 프로세스를 동시에 띄우면 10회 중 3회가
	// "pin map to ...: file exists" 로 실패했다 (S5, 2026-10-26).
	//
	// create-or-open 경쟁이므로 처리도 정해져 있다 — EEXIST 면 다시 연다.
	// 그때는 이미 pin 이 있으므로 재사용 경로로 들어간다. spec 은 매번 새로
	// 읽는다. 로드가 spec 을 건드렸을 가능성을 남기지 않기 위해서다.
	const attempts = 4

	var spec *ebpf.CollectionSpec
	var coll *ebpf.Collection
	for i := 0; ; i++ {
		var err error
		spec, err = ebpf.LoadCollectionSpec(objPath)
		if err != nil {
			return nil, fmt.Errorf("오브젝트 %s: %w", objPath, err)
		}

		// 맵마다 「이름으로 pin」 을 켠다. C 쪽에 LIBBPF_PIN_BY_NAME 을 안 적어도
		// 여기서 켜면 있으면 재사용, 없으면 만들어서 pin 한다.
		for _, m := range spec.Maps {
			if strings.HasPrefix(m.Name, ".") {
				continue // .rodata 같은 내부 맵은 pin 하지 않는다
			}
			m.Pinning = ebpf.PinByName
		}

		coll, err = ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{PinPath: pinDir},
		})
		if err == nil {
			break
		}

		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			// verifier 로그는 잘리면 원인을 못 찾는다. 통째로 넘긴다.
			return nil, fmt.Errorf("verifier 거부:\n%+v", ve)
		}
		if errors.Is(err, os.ErrExist) && i < attempts-1 {
			continue // 남이 먼저 pin 했다. 이제 열면 된다.
		}
		return nil, fmt.Errorf("로드: %w", err)
	}

	return &Loader{
		coll:    coll,
		spec:    spec,
		pinDir:  pinDir,
		linkDir: linkDir,
		links:   make(map[string]link.Link),
	}, nil
}

// AttachAll 은 모든 프로그램을 자기 훅에 붙이고 링크를 pin 한다.
//
// 이미 pin 된 링크가 있으면 그걸 집어 든다 — 두 번 붙이면 같은 훅에 프로그램이
// 두 개 매달려 판정이 중복된다.
//
// 하나라도 실패하면 그때까지 붙인 것을 전부 뗀다. 일부만 붙은 상태가 제일
// 위험하다 — 자기보호 하나가 빠진 채로 도는 것이기 때문이다 (§16).
func (l *Loader) AttachAll() error {
	names := make([]string, 0, len(l.coll.Programs))
	for name := range l.coll.Programs {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		err := l.attachOne(name)
		if err == nil {
			continue
		}
		// 미러(kprobe)는 못 붙어도 치명이 아니다. 커널마다 security_* 가
		// 인라인되거나 이름이 달라질 수 있는데, 그것 때문에 판정까지
		// 멈출 이유가 없다. LSM 훅이 하나라도 안 붙으면 그건 다르다 —
		// 자기보호가 빠진 채로 도는 것이므로 전부 뗀다 (§16).
		if l.spec.Programs[name].Type == ebpf.Kprobe {
			l.missing = append(l.missing,
				fmt.Sprintf("%s (%v)", l.spec.Programs[name].SectionName, err))
			continue
		}
		l.detachAll()
		return fmt.Errorf("%s: %w", name, err)
	}
	sort.Strings(l.attached)
	sort.Strings(l.missing)
	return nil
}

// MissingMirrors 는 안 붙은 감사 미러다. 비어 있어야 정상이고,
// 비어 있지 않으면 그 훅은 LSM 판정만 있고 대조가 없다는 뜻이다.
func (l *Loader) MissingMirrors() []string {
	out := make([]string, len(l.missing))
	copy(out, l.missing)
	return out
}

func (l *Loader) attachOne(name string) error {
	prog := l.coll.Programs[name]
	ps := l.spec.Programs[name]
	pinPath := filepath.Join(l.linkDir, name)

	// 이미 붙어 있으면 그걸 쓴다.
	ln, err := link.LoadPinnedLink(pinPath, nil)
	switch {
	case err == nil:
		l.links[name] = ln
		l.attached = append(l.attached, ps.SectionName)
		return nil
	case !errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("pin 된 링크 %s: %w", pinPath, err)
	}

	ln, err = attachByType(prog, ps)
	if err != nil {
		return err
	}
	if err := ln.Pin(pinPath); err != nil {
		ln.Close()
		return fmt.Errorf("링크 pin %s: %w", pinPath, err)
	}

	l.links[name] = ln
	l.attached = append(l.attached, ps.SectionName)
	return nil
}

// attachByType 은 SEC 종류에 따라 붙이는 방법을 고른다.
func attachByType(prog *ebpf.Program, ps *ebpf.ProgramSpec) (link.Link, error) {
	switch ps.Type {
	case ebpf.LSM:
		return link.AttachLSM(link.LSMOptions{Program: prog})

	case ebpf.Tracing:
		// tp_btf/* 가 여기로 온다.
		return link.AttachTracing(link.TracingOptions{Program: prog})

	case ebpf.Kprobe:
		sym := kprobeSymbol(ps)
		if sym == "" {
			return nil, fmt.Errorf("kprobe 심볼을 못 찾았다 (SEC %q)", ps.SectionName)
		}
		return link.Kprobe(sym, prog, nil)

	default:
		return nil, fmt.Errorf("붙이는 방법을 모르는 종류다: %s (SEC %q)", ps.Type, ps.SectionName)
	}
}

// kprobeSymbol 은 붙을 커널 함수 이름을 꺼낸다.
// AttachTo 가 비어 있으면 SEC 이름에서 떼어낸다 ("kprobe/security_file_open").
func kprobeSymbol(ps *ebpf.ProgramSpec) string {
	if ps.AttachTo != "" {
		return ps.AttachTo
	}
	if _, after, ok := strings.Cut(ps.SectionName, "/"); ok {
		return after
	}
	return ""
}

// AttachedHooks 는 붙어 있는 SEC 이름을 돌려준다.
// 올린 프로그램 수와 이 개수를 대조하면 누락이 바로 보인다.
func (l *Loader) AttachedHooks() []string {
	out := make([]string, len(l.attached))
	copy(out, l.attached)
	return out
}

// ProgramCount 는 올라간 프로그램 수다. AttachedHooks 와 대조하는 용도다.
func (l *Loader) ProgramCount() int { return len(l.coll.Programs) }

// Close 는 링크만 닫는다. pin 은 지우지 않는다.
//
// 그래서 warrantd 가 죽어도 판정은 계속된다 — 커널이 혼자 판정하고 링크는
// bpffs 가 들고 있다 (§10, §17).
func (l *Loader) Close() error {
	var errs []error
	for _, ln := range l.links {
		errs = append(errs, ln.Close())
	}
	l.links = make(map[string]link.Link)
	if l.coll != nil {
		l.coll.Close()
	}
	return errors.Join(errs...)
}

// Detach 는 pin 까지 지워서 실제로 훅을 뗀다. 끄는 경로에서만 쓴다.
func (l *Loader) Detach() error {
	var errs []error
	for name, ln := range l.links {
		errs = append(errs, ln.Unpin(), ln.Close())
		delete(l.links, name)
	}
	l.attached = nil
	return errors.Join(errs...)
}

// detachAll 은 AttachAll 중간 실패를 되돌린다.
func (l *Loader) detachAll() {
	for name, ln := range l.links {
		_ = ln.Unpin()
		_ = ln.Close()
		delete(l.links, name)
	}
	l.attached = nil
}

// lsmPath 는 커널이 켠 LSM 목록을 보여주는 곳이다.
var lsmPath = "/sys/kernel/security/lsm"

// BpfLsmEnabled 는 부팅 파라미터에 bpf LSM 이 들어갔는지 본다.
//
// 꺼져 있으면 lsm/* 프로그램은 아예 붙지 않는다. 런타임에 켤 수 없고 재부팅이
// 필요하다 — deploy/enable-bpf-lsm.sh 가 그 일을 한다.
func BpfLsmEnabled() (bool, error) {
	b, err := os.ReadFile(lsmPath)
	if err != nil {
		return false, fmt.Errorf("%s: %w", lsmPath, err)
	}
	return hasBPF(string(b)), nil
}

func hasBPF(list string) bool {
	for _, name := range strings.Split(strings.TrimSpace(list), ",") {
		if strings.TrimSpace(name) == "bpf" {
			return true
		}
	}
	return false
}
