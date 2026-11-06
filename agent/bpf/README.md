# agent/bpf/

컴파일된 BPF 오브젝트를 Go 바이너리에 임베드하는 자리. **`.o` 는 커밋한다.**

```sh
make -C agent bpf      # ../bpf 에서 컴파일 → 여기로 복사 → llvm-strip -g
```

## 왜 커밋하는가

노드로 **바이너리 하나만** 보내면 되게 하려는 것이다. `.o` 를 파일로 들고 가면 셋이 따라온다.

- 노드마다 clang 18+ 과 자기 커널의 `vmlinux.h` 가 있어야 한다
- `warrantd` 와 `.o` 의 버전이 어긋날 수 있다 — **이게 조용히 깨진다.** 새 `warrantd` 에 낡은 `.o` 를 물리면 맵 레이아웃이 안 맞는데, 로드 실패로 나오지 않고 엉뚱한 바이트를 읽는 쪽으로 나온다
- `deploy/systemd/install.sh` 가 복사할 파일이 하나 는다

그래서 생성물인데도 저장소에 들어온다. 루트 `.gitignore` 의 `*.o` · `*.bpf.o` 규칙에
**이 파일만** 예외가 걸려 있다(그 두 줄 뒤에 와야 효력이 있다).

없으면 `go:embed` 가 **컴파일 단계에서** 터져서 `agent/` 전체가 안 빌드된다.

## bpf2go 를 쓰지 않는 이유

기술 스택 문서는 `bpf2go` 를 적어 뒀지만 쓰지 않았다. `bpf2go` 는 생성기가
**자기 플래그로 clang 을 부른다.** 그러면 같은 C 소스가 두 가지 플래그로 컴파일되고
`bpf/wtest.sh` · `bench/` 가 보는 `.o` 와 Go 가 들고 있는 `.o` 가 달라질 수 있다 —
"bench 에서는 통과했는데 warrantd 에서는 아니다" 가 생기는 자리다. 지금 `make -C bpf` 는
`vmlinux.h` 에서 경고 5개를 내고 지나가는데, `bpf2go` 의 기본 플래그에는 `-Werror` 가
들어 있어 같은 소스가 에러로 멈춘다.

컴파일 경로를 `bpf/Makefile` 하나로 두고 Go 는 그 산출물을 임베드만 한다.
`bpf2go` 가 주는 타입 바인딩은 어차피 쓰지 않는다 — `loader` 는 `CollectionSpec` 을
직접 다루고, 맵은 `bpfmap` 이 자기 구조체로 쓴다.

`bpf2go` 로 옮기면 `bpf/Makefile` · `wtest.sh` · `bench/*` · `deploy/` 가 같이 바뀐다
(A 담당 밖이다).

**다만 `bpf2go -type` 은 지금 안 가져가는 이득이다.** `bpfmap` 의 `struct warrant` 는
손으로 쓴 Go 구조체이고, C 와 어긋나면 로드는 성공하고 엉뚱한 바이트를 읽는다.
`-type` 은 그걸 C 에서 생성해 그 클래스의 버그를 없앤다. 지금은 `layout_test.go` 가
offset 을 박아 막고 있다.

## strip

`llvm-strip -g` 로 DWARF만 뗀다 — 1,038KB → 359KB.

**`-s` · `--strip-all` 을 쓰면 안 된다.** `.BTF` · `.BTF.ext` 가 사라지고 CO-RE 가
깨진다. 빌드는 아무 말도 안 하고 노드에서 로드할 때 실패한다.
`TestEmbeddedObjectKeepsBTF` 가 그걸 잡는다.

`../bpf/warrant.bpf.o` 는 안 건드린다 — 거기선 디버그 정보가 쓸모가 있다.

## 낡은 `.o` 를 커밋하지 않기

훅을 새로 붙이고 여기로 들여오는 걸 잊으면 **테스트는 전부 초록인데 `warrantd` 는
훅 하나 적게 올린다.** S5 에서 낡은 바이너리를 사흘 돌린 적이 있다.

```sh
cd agent && go test ./internal/loader/ -run Embedded
```

`TestEmbeddedMatchesSource` 가 임베드된 쪽과 `bpf/warrant.bpf.o` 의 **프로그램 · 맵
목록**을 비교한다. 바이트로 비교하지 않는다 — clang 버전이나 `vmlinux.h` 가 다르면
같은 소스도 다른 바이트가 나오고, 그건 드리프트가 아니다.

`bpf/warrant.bpf.o` 가 없는 기계(맥북)에서는 skip 된다.

## 쓰는 쪽

```go
loader.Load(pinDir)            // 임베드된 것. 제품 경로
loader.LoadObject("", pinDir)  // 같다
loader.LoadObject(p, pinDir)   // 그 파일이 이긴다. 재임베드 없이 시험할 때
```

`warrantd` 는 `-bpf-obj` 기본값이 `/usr/lib/warrant/warrant.bpf.o` 라서 아직 파일을
읽는다. 임베드된 걸 쓰게 하려면 그 기본값을 `""` 로 바꾸고 `install.sh` 의 `.o` 복사를
지우면 된다 — 둘 다 C 담당 파일이다.
