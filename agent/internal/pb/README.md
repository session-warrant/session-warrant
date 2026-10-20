# internal/pb/

`proto/*.proto` 의 Go 생성물. **커밋한다** — 빌드 머신에 protoc 이 없어도 `go build` 가 서야 한다.
손으로 고치지 않는다. 고칠 일이 있으면 `.proto` 를 고치고 다시 생성한다.

```sh
make -C agent proto
```

| 파일 | 생성기 | 내용 |
|---|---|---|
| `warrant.pb.go` · `audit.pb.go` · `agent.pb.go` | `protoc-gen-go` | 메시지 · enum |
| `agent_grpc.pb.go` | `protoc-gen-go-grpc` | `WarrantPushService` · `AuditIngestService` 클라이언트 · 서버 |
| `pb_test.go` | — | oneof 왕복 · bufconn 위 `AuditIngestService.Stream` |

버전 (2026-10-20): protoc 36.2 (`brew install protobuf`) · protoc-gen-go v1.36.12 ·
protoc-gen-go-grpc v1.6.2. 플러그인은 `agent/go.mod` 의 `tool` 이 고정하고 Makefile 이
`go tool -n` 으로 경로를 넘긴다 — `go install` 로 PATH 에 깔지 않는다. protoc 버전이 다르면
생성 파일 머리 줄만 바뀐다. 서버는 protoc 35.1(protobuf-java 4.35.1)을 쓰지만 와이어 형식은 같다.

**누가 import 하는가.** `upstream` 과 `cmd/warrantd` 만. `bpfmap` · `ringbuf` · `policy` · `pamsock`
은 커널 레이아웃 쪽이라 와이어 타입에 묶지 않는다. `pb.Warrant` → `bpfmap.Warrant` 는
`upstream.ToKernel` 한 곳에서만 바꾼다.
