# S3 — PAM 타이밍 하네스
#
#   make                    pam_warrant_probe.so
#   make check              libpam-dev · pamtester · logind 확인
#   sudo make install       .so 를 PAM 모듈 디렉터리로 · 테스트 서비스 파일 생성
#   sudo make test          1단계 — pamtester (sshd 를 건드리지 않는다)
#   sudo make enable-su     2단계 — /etc/pam.d/su 에 삽입 (ssh 는 안전)
#   sudo make enable-sshd   3단계 — /etc/pam.d/sshd. 콘솔 확보 후에만
#   sudo make disable       삽입한 줄 전부 제거 + 백업 복원
#   sudo make collect       /run 로그를 out/ 로 옮기고 요약
#
# 단계를 건너뛰지 말 것. 1단계에서 모듈이 안 죽는 걸 본 뒤에 2단계,
# 2단계에서 진짜 logind 세션이 찍히는 걸 본 뒤에 3단계다.

SHELL   := /bin/bash
SO      := pam_warrant_probe.so
SECDIR  := $(shell dirname $$(ls /lib/*/security/pam_unix.so /lib/security/pam_unix.so 2>/dev/null | head -1) 2>/dev/null)
LOG     := /run/warrant-pamprobe.log
LINE    := session optional $(SO) wait_ms=200
MARK    := \# warrant-pamprobe (S3 스파이크 — 측정 뒤 반드시 제거)

.PHONY: all check install test test-detached enable-su enable-sshd disable collect clean

all: $(SO)

$(SO): pamprobe.c
	@echo "  CC    $@"
	@$(CC) -fPIC -shared -O2 -Wall -Wextra -o $@ $< -lpam

check:
	@echo "libpam-dev = $$(test -f /usr/include/security/pam_modules.h && echo 있음 || echo '없음 ← sudo apt install libpam0g-dev')"
	@echo "pamtester  = $$(command -v pamtester || echo '없음 ← sudo apt install pamtester')"
	@echo "SECDIR     = $(SECDIR)"
	@echo "logind     = $$(systemctl is-active systemd-logind 2>/dev/null || echo '안 돎 ← S3 이 성립하지 않는다')"
	@echo "cgroup v2  = $$(test -f /sys/fs/cgroup/cgroup.controllers && echo 예 || echo '아니오 ← §04 전제가 깨진다')"
	@echo "내 세션    = $$(awk -F: '$$1=="0"{print $$3}' /proc/self/cgroup)"

install: all
	@test "$$(id -u)" = 0 || { echo "ERROR: sudo make install"; exit 1; }
	@test -n "$(SECDIR)" || { echo "ERROR: PAM 모듈 디렉터리를 못 찾았다"; exit 1; }
	install -m 0644 $(SO) $(SECDIR)/$(SO)
	@printf '%s\n' \
	  '# S3 스파이크 전용 서비스. sshd 와 무관하다.' \
	  'auth     required   pam_permit.so' \
	  'account  optional   $(SO)' \
	  '@include common-session' \
	  'session  optional   $(SO) wait_ms=200' \
	  > /etc/pam.d/warrant-probe
	@echo "설치됨: $(SECDIR)/$(SO) · /etc/pam.d/warrant-probe"

# ── 1단계: pamtester. sshd 를 건드리지 않으므로 위험이 없다 ──────────
test: install
	@test "$$(id -u)" = 0 || { echo "ERROR: sudo make test"; exit 1; }
	@command -v pamtester >/dev/null || { echo "ERROR: sudo apt install pamtester"; exit 1; }
	@u=$${SUDO_USER:-root}; echo "── pamtester × 3 (user=$$u) ──"; \
	 for i in 1 2 3; do pamtester -v warrant-probe "$$u" open_session || true; done
	@echo; echo "── $(LOG) ──"; tail -20 $(LOG) 2>/dev/null || echo "(비어 있다)"

# ── 1.5단계: 세션 밖에서 pamtester. 여기서 답이 나올 수도 있다 ──────
#
# pam_systemd.so 는 호출한 프로세스가 이미 사용자 세션 안에 있으면 세션
# 생성을 건너뛴다 (데스크톱 터미널에서 돌리면 xdg_session_id=- 로 나온다).
# system.slice 로 빠져나가면 logind 가 세션을 만들 여지가 생긴다.
test-detached: install
	@test "$$(id -u)" = 0 || { echo "ERROR: sudo make test-detached"; exit 1; }
	@command -v pamtester >/dev/null || { echo "ERROR: sudo apt install pamtester"; exit 1; }
	@command -v systemd-run >/dev/null || { echo "ERROR: systemd-run 이 없다"; exit 1; }
	@u=$${SUDO_USER:-root}; echo "── system.slice 안에서 pamtester × 3 (user=$$u) ──"; \
	 for i in 1 2 3; do \
	   systemd-run --scope --slice=system.slice --quiet --collect \
	     pamtester -v warrant-probe "$$u" open_session || true; \
	 done
	@echo; echo "── 최근 기록 ──"; tail -5 $(LOG) 2>/dev/null || echo "(비어 있다)"
	@echo
	@if tail -5 $(LOG) 2>/dev/null | grep -q 'xdg_session_id=[0-9]'; then \
	   echo "✓ 세션이 만들어졌다. sudo make collect 로 판정할 것 —"; \
	   echo "  여기서 답이 나오면 3단계(sshd)는 확인용으로만 돌리면 된다."; \
	 else \
	   echo "✗ 여기서도 세션이 안 만들어졌다 (xdg_session_id=-)."; \
	   echo "  logind 가 TTY 없는 호출에 세션을 안 준다는 뜻이다."; \
	   echo "  → 3단계(sshd)로 간다. 그것만이 진짜 새 세션을 만든다."; \
	 fi

# ── 2단계: /etc/pam.d/su ────────────────────────────────────────────
# 주의: 기존 세션 안에서 su 를 하면 새 세션이 만들어지지 않는다.
# 이 단계로는 §11 T1 을 잴 수 없다 — 모듈이 su 경로에서도 안 죽는다는 것만 확인한다.
enable-su:
	@$(MAKE) --no-print-directory _patch F=/etc/pam.d/su

# ── 3단계: /etc/pam.d/sshd. 여기서만 잠길 수 있다 ────────────────────
enable-sshd:
	@test "$$I_HAVE_CONSOLE" = 1 || { \
	  echo "거부: 물리 콘솔 접근이 없으면 하지 않는다."; \
	  echo "  이 줄이 잘못 들어가면 SSH 로 다시 못 들어온다."; \
	  echo "  콘솔이 확보됐고 root 셸을 하나 열어 둔 상태라면:"; \
	  echo "    sudo I_HAVE_CONSOLE=1 make enable-sshd"; exit 1; }
	@echo "!! 지금 열려 있는 root 셸을 닫지 말 것. 되돌리기: sudo make disable"
	@$(MAKE) --no-print-directory _patch F=/etc/pam.d/sshd

# common-session 뒤에 넣는다. pam_systemd.so 가 그 안에 있고,
# 그보다 앞이면 session-N.scope 가 아직 없다 (§11 T1).
_patch:
	@test "$$(id -u)" = 0 || { echo "ERROR: sudo"; exit 1; }
	@test -f $(F) || { echo "ERROR: $(F) 가 없다"; exit 1; }
	@grep -q 'warrant-pamprobe' $(F) && { echo "이미 들어가 있다: $(F)"; exit 0; } || true
	@cp -a $(F) $(F).warrant-bak
	@awk -v mark='$(MARK)' -v line='$(LINE)' \
	   '{ print } /^[[:space:]]*(@include[[:space:]]+common-session|session.*pam_systemd\.so)/ && !d { print mark; print line; d=1 }' \
	   $(F).warrant-bak > $(F).new
	@grep -q 'warrant-pamprobe' $(F).new || { rm -f $(F).new; \
	   echo "ERROR: 삽입 지점을 못 찾았다 ($(F) 에 common-session 도 pam_systemd 도 없다)"; exit 1; }
	@mv $(F).new $(F)
	@echo "삽입됨: $(F)  (백업 $(F).warrant-bak)"
	@grep -n -A1 'warrant-pamprobe' $(F)

disable:
	@test "$$(id -u)" = 0 || { echo "ERROR: sudo make disable"; exit 1; }
	@for f in /etc/pam.d/sshd /etc/pam.d/su; do \
	   if [ -f $$f.warrant-bak ]; then mv $$f.warrant-bak $$f; echo "복원: $$f"; \
	   elif grep -q 'warrant-pamprobe' $$f 2>/dev/null; then \
	     sed -i '/warrant-pamprobe/,+1d' $$f; echo "제거: $$f"; fi; done
	@rm -f /etc/pam.d/warrant-probe
	@echo "남은 흔적:"; grep -rn 'warrant.pamprobe\|$(SO)' /etc/pam.d/ 2>/dev/null || echo "  없음"

collect:
	@test -s $(LOG) || { echo "ERROR: $(LOG) 가 비어 있다. 아직 아무 세션도 안 열렸다"; exit 1; }
	@mkdir -p out; ts=$$(date +%Y%m%d-%H%M%S); d=out/$$ts; mkdir -p $$d; \
	 { echo "kernel   $$(uname -r)"; \
	   echo "logind   $$(systemctl show systemd-logind -p Version --value 2>/dev/null || systemctl --version | head -1)"; \
	   echo "sshd     $$(sshd -V 2>&1 | head -1 || ssh -V 2>&1)"; \
	   echo "stack    $$(grep -c . /etc/pam.d/sshd) 줄 (sshd)"; \
	   echo "date     $$(date -Is)"; } > $$d/env.txt; \
	 cp $(LOG) $$d/pamprobe.log; \
	 : > $(LOG); \
	 python3 report.py $$d | tee $$d/report.txt; \
	 if [ -n "$$SUDO_USER" ]; then chown -R "$$SUDO_USER" out; fi; \
	 echo; echo "결과: $$d"; \
	 echo "커밋: git add bench/pamtiming/out && git commit -m \"S3 실측: $$(uname -r)\""

clean:
	rm -f $(SO)
