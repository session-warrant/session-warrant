# Session Warrant — BPF 빌드
#
#   make            smoke 스파이크 빌드
#   make V=1        실행되는 명령을 그대로 보여준다 (디버깅용)
#   make check      툴체인 경로만 확인
#   make vmlinux.h  이 커널의 BTF 덤프 (커밋하지 않는다 — 커널마다 다르다)
#   make clean
#
# clang 18+ 필요. 없으면 ../deploy/bootstrap.sh --install

CLANG   ?= $(shell command -v clang-19 || command -v clang-18 || command -v clang)
BPFTOOL ?= $(shell command -v bpftool || echo /usr/lib/linux-tools/$(shell uname -r)/bpftool)
ARCH    := $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/; s/ppc64le/powerpc/')

# -I/usr/include/<arch>-linux-gnu 는 asm/types.h 를 못 찾는 배포판을 위한 보험이다.
BPF_CFLAGS  := -g -O2 -Wall -target bpf -D__TARGET_ARCH_$(ARCH) \
               -I. -I/usr/include/$(shell uname -m)-linux-gnu
HOST_CFLAGS := -g -O2 -Wall
HOST_LDLIBS := -lbpf -lelf -lz

V ?= 0
ifeq ($(V),1)
  Q :=
else
  Q := @
endif

.PHONY: all clean check
# 없으면 make 가 %.bpf.o · %.skel.h 를 중간 산출물로 보고 지운다 (bpftool 로 못 들여다본다).
.SECONDARY:

all: smoke

vmlinux.h:
	@test -r /sys/kernel/btf/vmlinux || { \
	  echo "ERROR: /sys/kernel/btf/vmlinux 가 없다 — CO-RE 불가."; \
	  echo "       CONFIG_DEBUG_INFO_BTF=y 커널이 필요하다."; exit 1; }
	@test -x "$(BPFTOOL)" || { \
	  echo "ERROR: bpftool 을 못 찾았다 ($(BPFTOOL))."; \
	  echo "       sudo apt install linux-tools-\$$(uname -r)"; exit 1; }
	@echo "  BTF   $@  ($(shell uname -r))"
	$(Q)$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

%.bpf.o: %.bpf.c vmlinux.h
	@test -n "$(CLANG)" || { echo "ERROR: clang 이 없다. ../deploy/bootstrap.sh --install"; exit 1; }
	@echo "  BPF   $@"
	$(Q)$(CLANG) $(BPF_CFLAGS) -c $< -o $@

%.skel.h: %.bpf.o
	@echo "  SKEL  $@"
	$(Q)$(BPFTOOL) gen skeleton $< > $@

smoke: smoke.c smoke.skel.h
	@echo "  CC    $@"
	$(Q)$(CC) $(HOST_CFLAGS) -I. smoke.c -o $@ $(HOST_LDLIBS)
	@echo "  실행: sudo ./bpf/smoke"

check:
	@echo "CLANG   = $(CLANG)"
	@echo "BPFTOOL = $(BPFTOOL)"
	@echo "ARCH    = $(ARCH)"
	@echo "BTF     = $(shell test -r /sys/kernel/btf/vmlinux && echo 있음 || echo '없음 ← 문제')"
	@echo "libbpf  = $(shell pkg-config --modversion libbpf 2>/dev/null || echo '없음 ← sudo apt install libbpf-dev')"

clean:
	rm -f *.o *.skel.h smoke
	@echo "vmlinux.h 는 남겨둔다 (재생성이 느리다). 지우려면: rm bpf/vmlinux.h"
