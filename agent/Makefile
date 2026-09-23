# warrantd. 빌드는 맥북에서도 되지만 실행은 Linux · root 에서만 된다.

GO ?= go

.PHONY: build vet test proto bpf check clean

build:
	$(GO) build ./...

vet:
	$(GO) vet ./...

test:
	$(GO) test ./...

# proto/*.proto → internal/pb/. 생성물은 커밋한다.
proto:
	protoc -I ../proto \
		--go_out=. --go_opt=module=github.com/session-warrant/session-warrant/agent \
		--go-grpc_out=. --go-grpc_opt=module=github.com/session-warrant/session-warrant/agent \
		../proto/warrant.proto ../proto/audit.proto ../proto/agent.proto

# bpf2go 생성물 → agent/bpf/. clang 과 vmlinux.h 가 필요하다(서브 PC).
bpf:
	$(GO) generate ./...

check:
	@printf '%-22s' 'go'; $(GO) version 2>/dev/null || echo '없음 — https://go.dev/dl'
	@printf '%-22s' 'protoc'; protoc --version 2>/dev/null || echo '없음 — apt install protobuf-compiler / brew install protobuf'
	@printf '%-22s' 'protoc-gen-go'; protoc-gen-go --version 2>/dev/null || echo '없음 — go install google.golang.org/protobuf/cmd/protoc-gen-go@latest'
	@printf '%-22s' 'protoc-gen-go-grpc'; protoc-gen-go-grpc --version 2>/dev/null || echo '없음 — go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest'
	@printf '%-22s' 'clang'; clang --version 2>/dev/null | head -1 || echo '없음 — 서브 PC 에서만 필요'

clean:
	rm -f warrantd
