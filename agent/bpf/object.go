// Package bpf 는 컴파일된 BPF 오브젝트를 Go 바이너리 안에 들고 있다.
//
// 노드로 바이너리 하나만 보내면 되게 하려는 것이다. 파일로 들고 가면 셋이
// 따라온다 — 노드마다 clang 과 vmlinux.h 가 있어야 하고, warrantd 와 .o 의
// 버전이 어긋날 여지가 생기고, install.sh 가 복사할 파일이 하나 는다.
// 버전 어긋남은 조용히 깨진다: 새 warrantd 에 낡은 .o 를 물리면 맵 레이아웃이
// 안 맞는데, 그게 로드 실패로 안 나오고 엉뚱한 바이트를 읽는 쪽으로 나온다.
//
// .o 는 `make -C agent bpf` 가 bpf/ 에서 컴파일해 여기로 복사한다. 생성물이지만
// 커밋한다 — 그래야 clang 없는 기계에서도 `go build` 가 선다. .gitignore 의
// *.o 규칙에 이 파일만 예외가 걸려 있다.
//
// **컴파일 경로는 하나다 — bpf/Makefile.** bpf2go 를 쓰면 생성기가 자기 플래그로
// clang 을 부르는데, 그러면 같은 C 소스가 두 가지 플래그로 컴파일되고
// wtest.sh · bench 가 보는 .o 와 Go 가 들고 있는 .o 가 달라질 수 있다. 그 둘이
// 다르면 "bench 에서는 통과했는데 warrantd 에서는 아니다" 가 된다. 타입 바인딩은
// 어차피 쓰지 않는다 — loader 는 CollectionSpec 을 직접 다룬다.
package bpf

import _ "embed"

// Object 는 warrant.bpf.o 의 내용이다.
//
// CO-RE 라서 커널마다 다시 컴파일하지 않는다 — 이 바이트열 하나가 6.8 과 7.0
// 양쪽에 올라간다. 커널 구조체 오프셋은 로드할 때 .BTF 를 보고 맞춰진다.
//
//go:embed warrant.bpf.o
var Object []byte
