# S1 — file_open 오버헤드 4단 하네스
#
#   make               오브젝트 10개 + 로더
#   make V=1           명령을 그대로 보여준다
#   make clean
#
# 티어 A 는 오브젝트가 없다 — 훅을 안 붙이는 게 A 다.

BPFDIR  := ../../bpf
CLANG   ?= $(shell command -v clang-19 || command -v clang-18 || command -v clang)
BPFTOOL ?= $(shell command -v bpftool || echo /usr/lib/linux-tools/$(shell uname -r)/bpftool)
ARCH    := $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/; s/ppc64le/powerpc/')

BPF_CFLAGS  := -g -O2 -Wall -target bpf -D__TARGET_ARCH_$(ARCH) \
               -I$(BPFDIR) -I/usr/include/$(shell uname -m)-linux-gnu
HOST_CFLAGS := -g -O2 -Wall
HOST_LDLIBS := -lbpf -lelf -lz

V ?= 0
ifeq ($(V),1)
  Q :=
else
  Q := @
endif

# 매크로용(계측 없음) 과 마이크로용(PROBE=1) 을 따로 만든다.
# 한 빌드에서 둘 다 얻으려 하면 계측 비용이 측정값에 섞여 둘 다 틀린다.
PLAIN := gate_b.bpf.o gate_c.bpf.o gate_d.bpf.o gate_r.bpf.o gate_i.bpf.o
PROBE := gate_b_probe.bpf.o gate_c_probe.bpf.o gate_d_probe.bpf.o \
         gate_r_probe.bpf.o gate_i_probe.bpf.o

.PHONY: all clean check
.SECONDARY:
all: gate $(PLAIN) $(PROBE)

# BTF 는 bpf/ 가 만든 것을 그대로 쓴다. 커널에 묶인 파일을 두 군데서 만들지 않는다.
$(BPFDIR)/vmlinux.h:
	$(Q)$(MAKE) -C $(BPFDIR) vmlinux.h

define build_tier
$(1): gate.bpf.c $(BPFDIR)/vmlinux.h
	@test -n "$(CLANG)" || { echo "ERROR: clang 이 없다. ../../deploy/bootstrap.sh --install"; exit 1; }
	@echo "  BPF   $(1)  (TIER=$(2) PROBE=$(3) READ_WATCH=$(4))"
	$(Q)$(CLANG) $(BPF_CFLAGS) -DTIER=$(2) -DPROBE=$(3) -DREAD_WATCH=$(4) -c $$< -o $$@
endef

$(eval $(call build_tier,gate_b.bpf.o,1,0,0))
$(eval $(call build_tier,gate_c.bpf.o,2,0,0))
$(eval $(call build_tier,gate_d.bpf.o,3,0,0))
$(eval $(call build_tier,gate_r.bpf.o,3,0,1))
$(eval $(call build_tier,gate_i.bpf.o,3,0,2))
$(eval $(call build_tier,gate_b_probe.bpf.o,1,1,0))
$(eval $(call build_tier,gate_c_probe.bpf.o,2,1,0))
$(eval $(call build_tier,gate_d_probe.bpf.o,3,1,0))
$(eval $(call build_tier,gate_r_probe.bpf.o,3,1,1))
$(eval $(call build_tier,gate_i_probe.bpf.o,3,1,2))

gate: gate.c
	@echo "  CC    $@"
	$(Q)$(CC) $(HOST_CFLAGS) gate.c -o $@ $(HOST_LDLIBS)

check:
	@echo "CLANG     = $(CLANG)"
	@echo "BPFTOOL   = $(BPFTOOL)"
	@echo "BTF       = $(shell test -r /sys/kernel/btf/vmlinux && echo 있음 || echo '없음 ← 문제')"
	@echo "lsm       = $(shell cat /sys/kernel/security/lsm 2>/dev/null || echo '읽을 수 없음')"
	@echo "hyperfine = $(shell command -v hyperfine || echo '없음 ← sudo apt install hyperfine')"
	@echo "libbpf    = $(shell pkg-config --modversion libbpf 2>/dev/null || echo '없음')"

clean:
	rm -f *.bpf.o gate
