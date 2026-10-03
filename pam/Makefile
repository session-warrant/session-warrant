# pam_warrant.so — 빌드 · 설치 · 검증 사다리
#
#   make                       pam_warrant.so (심볼 검사까지)
#   make check                 도구 · 모듈 디렉터리 · logind · PrivateTmp
#   make status                설치본이 방금 빌드한 것과 같은가 · sshd 에 들어가 있나
#   sudo make install          .so 를 모듈 디렉터리로 · 테스트 서비스 생성
#   sudo make listen           테스트 수신기 (다른 터미널에 띄워 둔다)
#   sudo make test             1단계   — pamtester, 세션 안. sshd 를 안 건드린다
#   sudo make test-detached    1.5단계 — system.slice 에서. 세션 번호 · cgroup id 가 나온다
#   sudo I_CAN_RECOVER=1 make enable-sshd
#                              3단계   — /etc/pam.d/sshd 에 삽입. 복구 경로 확보 후에만
#   sudo make disable          삽입한 줄 · 테스트 서비스 제거
#   sudo make uninstall        disable + 모듈 파일 삭제
#
# 제품 설치(warrantd 와 붙일 때)는 socket= 인자 없이 넣는다:
#   sudo I_CAN_RECOVER=1 make enable-sshd PAM_ARGS=
#
# .so 는 빌드한 기계의 아키텍처에 묶인다. Lima VM(arm64) 에서 만든 걸
# 서브 PC(x86_64) 로 옮기지 말고 거기서 다시 빌드한다.

SHELL     := /bin/bash
SO        := pam_warrant.so
SRC       := pam_warrant.c
CFLAGS    := -std=c11 -D_GNU_SOURCE -fPIC -O2 -Wall -Wextra -Werror
SECDIR    := $(shell dirname $$(ls /lib/*/security/pam_unix.so /lib64/security/pam_unix.so /lib/security/pam_unix.so 2>/dev/null | head -1) 2>/dev/null)
TEST_SOCK ?= /tmp/warrant-test.sock
PAM_ARGS  ?= socket=$(TEST_SOCK)
SVC       := warrant-test
TAG       := warrant-pam-line
MARK      := \# $(TAG) — pam/Makefile 이 넣었다. sudo make -C pam disable 로 뺀다
LINE      := session  optional  $(SO) $(PAM_ARGS)

.PHONY: all check status install listen _need_listener test test-detached enable-sshd _patch disable uninstall clean

all: $(SO)

# 빌드 직후 목차를 본다. pam_sm_* 이름 오타와 static 누락은 컴파일러가 못 잡는다 —
# libpam 은 이름 문자열로 dlsym 하므로 로그인해 봐야 드러난다. 여기서 막는다.
$(SO): $(SRC)
	@echo "  CC    $@"
	@$(CC) $(CFLAGS) -shared -o $@ $< -lpam
	@n=$$(nm -D --defined-only $@ | grep -c ' pam_sm_'); \
	 leak=$$(nm -D --defined-only $@ | grep ' wr_' || true); \
	 if [ "$$n" != 6 ] || [ -n "$$leak" ]; then \
	   echo "ERROR: 심볼 검사 실패 — pam_sm_* $$n 개 (6 이어야 한다)"; \
	   [ -n "$$leak" ] && echo "  static 이 빠진 내부 함수: $$leak"; \
	   rm -f $@; exit 1; fi
	@echo "  NM    pam_sm_* 6개 · wr_* 노출 0"

check:
	@echo "arch       = $$(uname -m)   ← 이 기계에서 빌드한 .so 는 이 아키텍처 전용"
	@echo "cc         = $$(command -v $(CC) || echo '없음 ← sudo apt install build-essential')"
	@echo "libpam-dev = $$(test -f /usr/include/security/pam_modules.h && echo 있음 || echo '없음 ← sudo apt install libpam0g-dev')"
	@echo "pamtester  = $$(command -v pamtester || echo '없음 ← sudo apt install pamtester')"
	@echo "python3    = $$(command -v python3 || echo '없음 ← make listen 에 필요')"
	@echo "SECDIR     = $(if $(SECDIR),$(SECDIR),못 찾음 ← pam_unix.so 가 없다)"
	@echo "logind     = $$(systemctl is-active systemd-logind 2>/dev/null || echo '안 돎 ← session-N.scope 가 안 생긴다')"
	@echo "cgroup v2  = $$(test -f /sys/fs/cgroup/cgroup.controllers && echo 예 || echo '아니오 ← §04 전제가 깨진다')"
	@echo "ssh        = PrivateTmp=$$(systemctl show ssh -p PrivateTmp --value 2>/dev/null || echo '?')   ← yes 면 /tmp 소켓이 sshd 에게 안 보인다"
	@echo "내 세션    = $$(awk -F: '$$1=="0"{print $$3}' /proc/self/cgroup)"

# "고쳤는데 결과가 안 바뀐다"의 단골 원인: 빌드만 하고 설치를 안 했다.
status:
	@if [ -f $(SECDIR)/$(SO) ]; then \
	   if [ -f $(SO) ] && cmp -s $(SO) $(SECDIR)/$(SO); then echo "설치본  = 최신 ($(SECDIR)/$(SO))"; \
	   elif [ -f $(SO) ]; then echo "설치본  = ✗ 빌드본과 다르다 ← sudo make install"; \
	   else echo "설치본  = 있음 (빌드본 없음, 비교 불가)"; fi; \
	 else echo "설치본  = 없음"; fi
	@echo "sshd    = $$(grep -n '^[^#]*$(SO)' /etc/pam.d/sshd 2>/dev/null || echo '안 들어가 있다')"
	@echo "테스트  = $$(test -f /etc/pam.d/$(SVC) && echo /etc/pam.d/$(SVC) || echo '없음')"
	@echo "수신기  = $$(test -S $(TEST_SOCK) && echo "$(TEST_SOCK) 있음" || echo "$(TEST_SOCK) 없음 ← sudo make listen")"

# install 은 cp 가 아니다 — 새 파일(새 inode)로 바꿔 넣어서, 옛 .so 를 이미 올린
# sshd 프로세스가 발밑에서 코드가 바뀌어 죽지 않게 한다.
# 모듈 파일은 root 소유 0644 여야 한다. sshd 안에서 root 로 돈다.
install: all
	@test "$$(id -u)" = 0 || { echo "ERROR: sudo make install"; exit 1; }
	@test -n "$(SECDIR)" || { echo "ERROR: PAM 모듈 디렉터리를 못 찾았다 (pam_unix.so 가 없다)"; exit 1; }
	install -o root -g root -m 0644 $(SO) $(SECDIR)/$(SO)
	@printf '%s\n' \
	  '# pam/Makefile 의 테스트 서비스. sshd 와 무관하다. sudo make -C pam disable 로 지운다.' \
	  'auth     required  pam_permit.so' \
	  'account  required  pam_permit.so' \
	  '@include common-session' \
	  'session  optional  $(SO)  socket=$(TEST_SOCK)' \
	  > /etc/pam.d/$(SVC)
	@echo "설치됨: $(SECDIR)/$(SO) · /etc/pam.d/$(SVC)"

listen:
	@test "$$(id -u)" = 0 || { echo "ERROR: sudo make listen (소켓을 root 전용 0600 으로 만든다)"; exit 1; }
	@python3 listen.py $(TEST_SOCK)

_need_listener:
	@test -S $(TEST_SOCK) || echo "!! $(TEST_SOCK) 이 없다 — 다른 터미널에서 sudo make listen. (없어도 로그인은 된다: fail-open)"

# ── 1단계: 세션 안. 모듈이 로드되고 안 죽고 형식대로 보내는지 ──────────
# 세션 번호는 '-' · cgroup id 는 0 으로 나오는 게 정상이다. 이미 세션 안이라
# pam_systemd.so 가 새 세션을 안 만든다 (S3 에서 두 번 헛돈 이유).
test: install _need_listener
	@command -v pamtester >/dev/null || { echo "ERROR: sudo apt install pamtester"; exit 1; }
	pamtester -v $(SVC) "$${SUDO_USER:-root}" open_session close_session
	@echo "→ 수신기에 OPEN · CLOSE 두 줄. 세션 번호 '-' · cgroup id 0 이면 정상"

# ── 1.5단계: 세션 밖(system.slice). 세션 번호 · cgroup id 가 실제 값으로 ──
# 세션 번호가 c1 처럼 나올 수 있다. 이 서비스엔 pam_loginuid.so 가 없어 logind 가
# audit 세션 id 대신 c+카운터를 쓴다 (docs/experiments.md S3 후속). 문자열로 다룰 것.
test-detached: install _need_listener
	@command -v pamtester >/dev/null || { echo "ERROR: sudo apt install pamtester"; exit 1; }
	systemd-run --scope --slice=system.slice --quiet --collect \
	  pamtester -v $(SVC) "$${SUDO_USER:-root}" open_session close_session
	@echo "→ cgroup id 가 0 이 아니고 OPEN · CLOSE 가 같으면 정상"

# ── 3단계: /etc/pam.d/sshd. 여기서만 잠길 수 있다 ────────────────────
# Lima VM 은 콘솔이 없고 limactl shell 도 VM 안의 sshd 를 거친다. 그래서 조건이
# "콘솔"이 아니라 "복구 경로"다 — 물리 콘솔, 또는 VM 디스크 백업 + 열어 둔 root 셸.
enable-sshd:
	@test "$$I_CAN_RECOVER" = 1 || { \
	  echo "거부: 복구 경로를 확보하지 않았다. 이 줄이 잘못 들어가면 SSH 로 다시 못 들어온다."; \
	  echo "  서브 PC : 물리 콘솔 확보"; \
	  echo "  Lima VM : 맥에서 limactl stop sw && cp -c ~/.lima/sw/disk ~/.lima/sw/disk.before-pam && limactl start sw"; \
	  echo "  둘 다   : root 셸 하나를 열어 두고 닫지 않는다"; \
	  echo "  준비됐으면: sudo I_CAN_RECOVER=1 make enable-sshd"; exit 1; }
	@case "$(PAM_ARGS)" in *socket=/tmp/*) \
	  [ "$$(systemctl show ssh -p PrivateTmp --value 2>/dev/null)" = yes ] && { \
	    echo "ERROR: ssh 가 PrivateTmp=yes 다. sshd 에겐 $(TEST_SOCK) 이 안 보인다 — TEST_SOCK=/run/... 로"; exit 1; } ;; esac; true
	@test -f $(SECDIR)/$(SO) || { echo "ERROR: 모듈이 설치 안 됐다 — sudo make install 먼저"; exit 1; }
	@echo "!! 열어 둔 root 셸을 닫지 말 것. 새 접속은 맥에서: ssh -o ControlPath=none lima-sw"
	@echo "   (ControlMaster 로 다중화된 접속은 PAM 세션을 새로 열지 않는다)"
	@$(MAKE) --no-print-directory _patch F=/etc/pam.d/sshd

# common-session 뒤, pam_selinux.so open 앞. pam_systemd.so 가 common-session 안에 있고
# 그보다 앞이면 session-N.scope 가 아직 없다 (§11 T1). selinux open 뒤는 사용자 문맥이다.
_patch:
	@test "$$(id -u)" = 0 || { echo "ERROR: sudo"; exit 1; }
	@test -f $(F) || { echo "ERROR: $(F) 가 없다"; exit 1; }
	@if grep -q '$(TAG)' $(F); then echo "이미 들어가 있다:"; grep -n -A1 '$(TAG)' $(F); exit 0; fi; \
	 cp -a $(F) $(F).$(TAG)-bak; \
	 awk -v mark='$(MARK)' -v line='$(LINE)' \
	   '{ print } /^[[:space:]]*(@include[[:space:]]+common-session|session.*pam_systemd\.so)/ && !d { print mark; print line; d=1 }' \
	   $(F).$(TAG)-bak > $(F).new; \
	 grep -q '$(TAG)' $(F).new || { rm -f $(F).new; \
	   echo "ERROR: 삽입 지점을 못 찾았다 ($(F) 에 common-session 도 pam_systemd 도 없다)"; exit 1; }; \
	 mv $(F).new $(F); \
	 echo "삽입됨: $(F)  (백업 $(F).$(TAG)-bak)"; grep -n -A1 '$(TAG)' $(F)

# 백업으로 통째로 되돌리지 않는다 — 넣은 뒤 다른 사람이 고친 줄까지 날아간다.
# 표시(TAG)가 붙은 두 줄만 뺀다.
disable:
	@test "$$(id -u)" = 0 || { echo "ERROR: sudo make disable"; exit 1; }
	@if grep -q '$(TAG)' /etc/pam.d/sshd 2>/dev/null; then \
	   sed -i '/$(TAG)/,+1d' /etc/pam.d/sshd; echo "제거: /etc/pam.d/sshd"; fi
	@rm -f /etc/pam.d/sshd.$(TAG)-bak /etc/pam.d/$(SVC)
	@echo "남은 흔적:"; grep -rn '$(SO)\|$(TAG)' /etc/pam.d/ 2>/dev/null || echo "  없음"

uninstall: disable
	@rm -f $(SECDIR)/$(SO) && echo "삭제: $(SECDIR)/$(SO)"

clean:
	rm -f $(SO)
