# internal/pb/

`proto/*.proto` 의 Go 생성물 자리. **커밋한다** — 빌드 머신에 protoc 이 없어도 `go build` 가 서야 한다.

`proto/warrant.proto` 의 `go_package` 가 이 경로를 가리킨다:

```
github.com/session-warrant/session-warrant/agent/internal/pb;pb
```

생성 (protoc · protoc-gen-go · protoc-gen-go-grpc 가 있어야 한다):

```sh
make -C agent proto
```

아직 생성하지 않았다. proto 는 2026-09-23 에 확정됐고 Java 쪽만 실증돼 있다 —
여기서 한 번 뽑아 봐야 `go_package` 경로와 `java_multiple_files=false` 같은 옵션이
세 언어 모두에서 서는지 확인된다.
