# warrantd. 빌드는 맥북에서도 되지만 실행은 Linux · root 에서만 된다.

GO ?= go

.PHONY: build vet test proto bpf check clean

build:
	$(GO) build ./...

vet:
	$(GO) vet ./...

test:
	$(GO) test ./...

# proto/*.proto → internal/pb/. 생성물은 커밋한다. 플러그인 버전은 go.mod 의 tool 이 고정한다.
proto:
	protoc -I ../proto \
		--plugin=protoc-gen-go=$$($(GO) tool -n protoc-gen-go) \
		--plugin=protoc-gen-go-grpc=$$($(GO) tool -n protoc-gen-go-grpc) \
		--go_out=. --go_opt=module=github.com/session-warrant/session-warrant/agent \
		--go-grpc_out=. --go-grpc_opt=module=github.com/session-warrant/session-warrant/agent \
		../proto/warrant.proto ../proto/audit.proto ../proto/agent.proto

# bpf/ 의 C → agent/bpf/warrant.bpf.o. clang 과 vmlinux.h 가 필요하다(서브 PC · VM).
#
# 컴파일은 ../bpf/Makefile 이 한다 — 플래그가 한 군데만 있어야 wtest.sh · bench 가
# 보는 .o 와 Go 가 들고 있는 .o 가 같은 것이 된다.
#
# 생성물이지만 커밋한다. 없으면 go:embed 가 컴파일 단계에서 터진다.
BPF_OBJ    := bpf/warrant.bpf.o
LLVM_STRIP ?= $(shell command -v llvm-strip-19 || command -v llvm-strip-18 || command -v llvm-strip)

bpf:
	$(MAKE) -C ../bpf warrant.bpf.o
	@echo "  COPY  $(BPF_OBJ)"
	@cp ../bpf/warrant.bpf.o $(BPF_OBJ)
	@# DWARF 만 뗀다. .BTF · .BTF.ext 는 CO-RE 에 필요하므로 남는다 (-s 를 쓰면 안 된다).
	@# ../bpf/warrant.bpf.o 는 건드리지 않는다 — 거기선 디버그 정보가 쓸모가 있다.
	@if [ -n "$(LLVM_STRIP)" ]; then \
	  $(LLVM_STRIP) -g $(BPF_OBJ); \
	  echo "  STRIP $(BPF_OBJ)  (DWARF 제거 · .BTF 유지)"; \
	else \
	  echo "  NOTE  llvm-strip 이 없다 — DWARF 가 남아 .o 가 3배쯤 크다. 동작은 같다"; \
	fi
	@printf '  SIZE  %s\n' "$$(wc -c < $(BPF_OBJ)) bytes"
	@echo
	@echo "  낡은 걸 커밋하지 않으려면: $(GO) test ./internal/loader/ -run Embedded"
	@echo "  커밋: git add $(BPF_OBJ)"

check:
	@printf '%-22s' 'go'; $(GO) version 2>/dev/null || echo '없음 — https://go.dev/dl'
	@printf '%-22s' 'protoc'; protoc --version 2>/dev/null || echo '없음 — apt install protobuf-compiler / brew install protobuf'
	@printf '%-22s' 'protoc-gen-go'; $(GO) tool protoc-gen-go --version 2>/dev/null || echo '없음 — go.mod 의 tool 확인'
	@printf '%-22s' 'protoc-gen-go-grpc'; $(GO) tool protoc-gen-go-grpc --version 2>/dev/null || echo '없음 — go.mod 의 tool 확인'
	@printf '%-22s' 'clang'; clang --version 2>/dev/null | head -1 || echo '없음 — 서브 PC 에서만 필요'
	@printf '%-22s' 'llvm-strip'; echo '$(LLVM_STRIP)' | grep -q . && echo '$(LLVM_STRIP)' || echo '없음 — .o 가 커지는 것뿐'
	@printf '%-22s' '임베드된 BPF'; test -f $(BPF_OBJ) \
		&& printf '%s bytes\n' "$$(wc -c < $(BPF_OBJ))" \
		|| echo '없음 ← go build 가 안 선다. make bpf'

clean:
	rm -f warrantd
