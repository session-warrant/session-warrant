# agent/bpf/

`bpf2go` 생성물 자리 (`.go` + 임베드된 `.o`). **커밋한다.**

`bpf/` 디렉터리의 C 소스를 clang 으로 컴파일한 결과를 Go 에 임베드한 것이다.
빌드 머신에 clang 과 `vmlinux.h` 가 없어도 `go build` 가 서게 하려는 것이고,
그래서 생성물이 저장소에 들어온다.

생성:

```sh
make -C agent bpf
```

아직 비어 있다 — `bpf/` 에 제품 BPF 코드가 없다(`smoke.bpf.c` 만 있다).
