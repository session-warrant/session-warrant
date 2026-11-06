#!/usr/bin/env bash
# S5 — 제품 오브젝트가 진짜 session-N.scope 에서 판정하는가.
#
# 문서의 S4 는 inode 안정성이다 — 이건 그게 아니다. docs/experiments.md 의
# 「다음」 4번(S2 재실행, 진짜 session-N.scope)을 포함하면서 그보다 넓다:
# 태그 전파만 보는 게 아니라 exec·쓰기 게이트와 observe·dryrun·enforce
# 세 모드를 제품 오브젝트(warrant.bpf.o)로 본다.
#
# wtest.sh 는 손으로 만든 cgroup 을 썼다. systemd 가 만드는 세션 scope 는
# 경로가 user.slice/user-N.slice/session-N.scope 이고 sshd 가 fork 한 셸이
# 그 안에서 시작한다. 그 구조에서도 2중 태깅이 도는지가 S5 의 전제다.
#
# 구조
#   조종석(이 셸)은 영장 밖에 있어야 한다 — 자기보호가 bpf() 를 막으므로
#   영장 안에서 돌리면 맵을 못 건드린다. 대상 세션은 ssh localhost 로 따로
#   만들고 ControlMaster 로 붙여 둔다. 그래야 명령마다 같은 세션 scope 를
#   쓴다 (새로 ssh 하면 scope 가 매번 달라져 태그가 안 맞는다).
#
#   돌리기:  ./bpf/vsession.sh            observe · dryrun 까지
#            ./bpf/vsession.sh --enforce  강제 모드까지
#
# 각 단계는 「무엇이 참이면 통과인가」와 「무엇 때문에 헛돌 수 있는가」를
# 같이 적는다. 지금까지 헛돈 네 번이 전부 그걸 안 적어서 생겼다.

set -uo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
OBJ=$ROOT/bpf/warrant.bpf.o
PIN=/sys/fs/bpf/vs
CTL=${TMPDIR:-/tmp}/vsession.ssh
LOGDIR=${TMPDIR:-/tmp}/vsession-logs
LOG=$LOGDIR/boot.log
WORK=${TMPDIR:-/tmp}/vswork
CTLBIN=$ROOT/agent/warrantctl
ESCAPE_CG=/sys/fs/cgroup/vsescape

DO_ENFORCE=0
[ "${1:-}" = "--enforce" ] && DO_ENFORCE=1

pass=0 fail=0
ok()   { pass=$((pass+1)); printf '  \033[32m통과\033[0m  %s\n' "$1"; }
no()   { fail=$((fail+1)); printf '  \033[31m실패\033[0m  %s\n' "$1"; }
step() { printf '\n\033[1m── %s\033[0m\n' "$1"; }
die()  { printf '\033[31m중단\033[0m %s\n' "$1" >&2; exit 1; }

# ── 정리 ──────────────────────────────────────────────────────────
# 어떤 경로로 끝나도 태그를 떼고 훅을 뗀다. 안 떼면 대상 세션이 계속
# 판정 아래 남는다.
cleanup() {
	local rc=$?
	step "정리"
	if [ -n "${WCTL_PID:-}" ] && kill -0 "$WCTL_PID" 2>/dev/null; then
		sudo kill -TERM "$WCTL_PID" 2>/dev/null
		wait "$WCTL_PID" 2>/dev/null
	fi
	# 태그 제거 — warrantctl 이 떼 주지만 죽었을 경우를 대비해 한 번 더.
	if [ -e "$PIN/cgroup_tag" ] && [ -n "${TCG:-}" ]; then
		printf '%s' "$TCG" | sudo bpftool map delete pinned "$PIN/cgroup_tag" \
			key hex $(u64hex "$TCG") 2>/dev/null \
			&& echo "  cgroup 태그 제거" || true
	fi
	sudo rm -rf "$PIN" 2>/dev/null && echo "  pin 제거"
	ssh -S "$CTL" -O exit localhost 2>/dev/null && echo "  ssh 세션 종료"
	[ -n "${SUDO_KEEP:-}" ] && kill "$SUDO_KEEP" 2>/dev/null
	[ -n "${OUT_PID:-}" ] && kill "$OUT_PID" 2>/dev/null
	# 탈출용 cgroup 에 남은 프로세스를 반드시 거둔다.
	#
	# 세션 scope 를 벗어난 프로세스는 scope 가 비어도 logind 가 여전히 그
	# pid 를 세션 소속으로 추적한다. 그게 안 죽으면 세션이 영원히 closing
	# 이고, systemd job 큐가 거기 막혀 새 ssh 로그인이 전부 멈춘다.
	# 한 번 그 상태로 박스가 잠겨서 재부팅했다.
	if [ -e "$ESCAPE_CG/cgroup.procs" ]; then
		n=$(sudo wc -l < "$ESCAPE_CG/cgroup.procs" 2>/dev/null || echo 0)
		if [ "${n:-0}" -gt 0 ]; then
			echo "  탈출 cgroup 에 남은 프로세스 ${n}개 — 죽인다"
			sudo sh -c "xargs -r kill -9 < $ESCAPE_CG/cgroup.procs" 2>/dev/null
			sleep 0.3
		fi
	fi
	sudo rmdir "$ESCAPE_CG" 2>/dev/null && echo "  탈출 cgroup 제거"
	rm -rf "$WORK"
	echo
	printf '로그: %s/\n' "$LOGDIR"
	printf '통과 %d · 실패 %d\n' "$pass" "$fail"
	[ "$fail" -eq 0 ] || rc=1
	exit $rc
}
trap cleanup EXIT INT TERM

rm -rf "$LOGDIR"; mkdir -p "$LOGDIR"

# u64 를 bpftool 이 받는 리틀엔디안 바이트열로 바꾼다.
u64hex() {
	python3 -c 'import sys;print(" ".join("%02x"%b for b in int(sys.argv[1]).to_bytes(8,"little")))' "$1"
}

# cgroup v2 의 cgroup id 는 그 디렉터리의 inode 번호다.
cgid_of_pid() {
	local p=$1 rel
	rel=$(cut -d: -f3 "/proc/$p/cgroup" 2>/dev/null) || return 1
	stat -c %i "/sys/fs/cgroup$rel" 2>/dev/null
}

# ── 0. 전제 ───────────────────────────────────────────────────────
step "0. 전제 확인"

grep -qw bpf /sys/kernel/security/lsm \
	|| die "bpf LSM 이 꺼져 있다. deploy/enable-bpf-lsm.sh 후 재부팅."
ok "bpf LSM 켜짐"

# sudo 를 미리 인증하고 그 동안 유지한다.
#
# start_warrant 는 warrantctl 을 백그라운드 sudo 로 띄우는데, 그 시점에
# sudo 가 암호를 요구하면 프롬프트와 실패 메시지가 stderr 가 아니라
# /dev/tty 로 직접 나간다 — 리다이렉트한 로그에는 한 글자도 안 남고
# 프로세스만 사라진다. 실제로 5단계가 0바이트 로그를 남기고 죽었다.
sudo -v || die "sudo 인증 실패"
( while true; do sleep 30; sudo -n true 2>/dev/null || exit; done ) &
SUDO_KEEP=$!
ok "sudo 인증 유지 중"

# 항상 make 를 거친다. 「없을 때만 빌드」로 두면 .c 를 고친 뒤 옛 오브젝트를
# 재는 사고가 난다 — make 가 알아서 최신인지 판단한다.
make -C "$ROOT/bpf" warrant.bpf.o >/dev/null || die "bpf 빌드 실패"
ok "오브젝트 $(basename "$OBJ") ($(date -r "$OBJ" '+%H:%M:%S'))"

# 항상 빌드한다. 「없을 때만」으로 두면 Go 쪽을 고친 뒤 낡은 바이너리를 재는
# 사고가 난다 — 실제로 policy 와 loader 수정이 둘 다 안 들어간 채로 사흘을 돌았다.
# go build 는 바뀐 게 없으면 캐시로 즉시 끝난다.
( cd "$ROOT/agent" && go build -o warrantctl ./cmd/warrantctl ) || die "warrantctl 빌드 실패"
ok "warrantctl ($(date -r "$CTLBIN" '+%H:%M:%S'))"

# 이전 실행 잔재. 핀된 링크는 프로세스가 죽어도 훅에 붙은 채로 남는다 —
# 그게 설계된 동작이지만(§10·§17), 중단된 실행이 남겨놓으면 다음 실행이
# 느려지고 낡은 영장이 새 세션에 걸릴 수 있다 (cgroup id 는 디렉터리 inode
# 번호라서 재사용된다). 실제로 한 번 1단계·4단계가 통째로 멈췄다.
stale_progs=$(sudo bpftool prog show 2>/dev/null | grep -cE 'lsm|tracing|kprobe')
stale_pin=0; [ -e "$PIN" ] && stale_pin=1
stale_proc=0; pgrep -f "$(basename "$CTLBIN")" >/dev/null 2>&1 && stale_proc=1
if [ "$stale_progs" -gt 0 ] || [ "$stale_pin" -eq 1 ] || [ "$stale_proc" -eq 1 ]; then
	echo "  이전 실행 잔재를 치운다 (프로그램 $stale_progs · pin $stale_pin · 프로세스 $stale_proc)"
	sudo pkill -f "$(basename "$CTLBIN")" 2>/dev/null
	sleep 1
	sudo rm -rf "$PIN"
	ssh -S "$CTL" -O exit localhost 2>/dev/null
	rm -f "$CTL"
	sudo sh -c "xargs -r kill -9 < $ESCAPE_CG/cgroup.procs" 2>/dev/null
	sudo rmdir "$ESCAPE_CG" 2>/dev/null
	# 프로그램 해제는 비동기다 (RCU 유예). 한 번만 보고 판단하면 「아직
	# 치우는 중」을 「안 치워진다」로 읽는다 — 실제로 그렇게 멈췄다.
	left=99
	for _ in $(seq 1 20); do
		left=$(sudo bpftool prog show 2>/dev/null | grep -cE 'lsm|tracing|kprobe')
		[ "$left" -eq 0 ] && break
		sleep 0.5
	done
	if [ "$left" -gt 0 ]; then
		die "프로그램 $left 개가 10초 뒤에도 붙어 있다. 다른 것이 들고 있다 — 재부팅이 가장 빠르다
      확인: sudo bpftool prog show | grep -E 'lsm|tracing|kprobe'
            sudo bpftool link show"
	fi
	ok "잔재 없음"
else
	ok "잔재 없음"
fi

MYCG=$(cgid_of_pid $$) || die "내 cgroup id 를 못 읽었다"
MYPATH=$(cut -d: -f3 /proc/self/cgroup)
echo "  조종석: cgroup $MYCG  $MYPATH"

# ── 1. 대상 세션 만들기 ───────────────────────────────────────────
step "1. 진짜 session scope 를 가진 대상 세션"

# 키 없이 ssh 가 되는지. 없으면 만든다 — 이게 없으면 전부 수동이 된다.
if ! timeout 15 ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
	localhost true 2>/dev/null; then
	echo "  localhost 무암호 ssh 가 안 된다 — 키를 만든다"
	[ -f ~/.ssh/id_ed25519 ] || ssh-keygen -t ed25519 -N '' -f ~/.ssh/id_ed25519 >/dev/null
	ssh-copy-id -o StrictHostKeyChecking=no localhost >/dev/null 2>&1 \
		|| die "ssh-copy-id 실패. sshd 가 떠 있는지 확인: systemctl status ssh"
	ssh -o BatchMode=yes localhost true 2>/dev/null \
		|| die "키를 넣었는데도 무암호 ssh 가 안 된다"
fi
ok "localhost 무암호 ssh"

rm -f "$CTL"
# ControlPersist 는 짧게 둔다. 길게 두면 중단된 실행의 마스터가 살아남아
# 다음 실행과 섞인다.
timeout 20 ssh -o BatchMode=yes -o StrictHostKeyChecking=no \
    -o ControlMaster=yes -o ControlPath="$CTL" -o ControlPersist=60 \
    -fN localhost || die "ControlMaster 를 못 열었다 (20초). sshd·logind 상태를 봐라:
      loginctl list-sessions   # closing 에서 안 끝나는 세션이 있으면 그게 원인이다
      systemctl status systemd-logind"

# 대상 세션에서 명령을 돌린다. 같은 마스터를 타므로 세션 scope 가 같다.
#
# timeout 을 반드시 건다. ssh 가 멈추면 스크립트가 통째로 매달려서 무엇이
# 잘못됐는지도 모른 채 기다리게 된다 — 실제로 그렇게 두 번 멈췄다.
# (원인은 logind 세션이 closing 에서 안 끝나 systemd job 큐가 막힌 것이었다.)
R() { timeout "${R_TIMEOUT:-30}" ssh -o ControlPath="$CTL" localhost "$@"; }

R true >/dev/null 2>&1 || die "대상 세션에서 명령이 안 돈다"

# cgroup 은 대상 세션 '안에서' 읽는다. 바깥에서 /proc/<pid>/cgroup 을 읽으면
# 그 pid 는 명령이 끝나는 순간 사라져서 항상 실패한다.
# 세션 scope 디렉터리 자체는 ControlMaster 가 붙어 있는 동안 남아 있다.
read -r TCG TPATH <<<"$(R 'rel=$(cut -d: -f3 /proc/self/cgroup); printf "%s %s" "$(stat -c %i "/sys/fs/cgroup$rel" 2>/dev/null)" "$rel"')"
case "${TCG:-}" in
	''|*[!0-9]*) die "대상 cgroup id 를 못 읽었다 (받은 값: '${TCG:-}' / 경로 '${TPATH:-}')" ;;
esac
echo "  대상: cgroup $TCG  $TPATH"

# 여기서 안 걸리면 다음 단계가 전부 무의미해진다 —
# 조종석을 태그하면 자기보호가 bpf() 를 막아 맵을 못 건드린다.
[ "$TCG" != "$MYCG" ] || die "대상이 조종석과 같은 cgroup 이다. 영장 안에서 돌리면 안 된다"
ok "대상이 조종석과 다른 cgroup"

case "$TPATH" in
	*/session-*.scope) ok "대상이 진짜 session-N.scope ($(basename "$TPATH"))" ;;
	*) no "대상 cgroup 이 session scope 가 아니다: $TPATH — pam_systemd 가 안 붙었다" ;;
esac

# 두 번째 명령도 같은 scope 인지. ControlMaster 가 안 먹으면 매번 달라지고
# 그러면 태그가 첫 명령에만 맞아 "판정이 안 돈다"는 틀린 답이 나온다.
TCG2=$(R 'rel=$(cut -d: -f3 /proc/self/cgroup); stat -c %i "/sys/fs/cgroup$rel"')
[ "$TCG2" = "$TCG" ] && ok "명령마다 같은 scope 를 쓴다 (ControlMaster 동작)" \
                     || no "명령마다 scope 가 달라진다 ($TCG vs $TCG2) — 멀티플렉싱이 안 된다"

# ── 2. 픽스처 ─────────────────────────────────────────────────────
step "2. 픽스처"

rm -rf "$WORK"; mkdir -p "$WORK/open" "$WORK/secret"
echo seed > "$WORK/open/f"
echo seed > "$WORK/secret/f"

# 심볼릭 링크 함정: 커널은 exec 시점에 링크의 '대상' 을 연다.
# 허용 목록에 링크 자신의 inode 를 넣으면 전부 조용히 안 걸린다.
SH=$(readlink -f /bin/sh)
BASH=$(readlink -f "$(R 'echo $SHELL')" 2>/dev/null || readlink -f /bin/bash)
TRUE=$(readlink -f /usr/bin/true)
SLEEP=$(readlink -f /usr/bin/sleep)   # 7단계 프로브가 쓴다
SUDO=$(readlink -f /usr/bin/sudo)
ID=$(readlink -f /usr/bin/id)
# 8단계 프로브. 없으면 그 단계는 「측정 안 됨」으로 적는다.
PY=""
if command -v python3 >/dev/null 2>&1; then PY=$(readlink -f "$(command -v python3)"); fi
echo "  sh=$SH  bash=$BASH  true=$TRUE  sudo=$SUDO  sleep=$SLEEP  (허용 밖: id=$ID)"

# 셸($SH · $BASH)을 일부러 안 넣는다. policy 의 기본 허용 세트가 넣어야 하고,
# 안 넣으면 sshd 가 로그인 셸을 exec 못 해 세션이 통째로 죽는다 — 여기 적어두면
# 그 기본값이 사라져도 아무도 모른다.
ALLOW_EXEC="$TRUE,$SUDO,$SLEEP${PY:+,$PY}"
ALLOW_WRITE="$WORK/open"
DENY_WRITE="$WORK/secret"

# ── warrantctl 띄우기 ─────────────────────────────────────────────
# 로그는 단계마다 따로 남긴다. 한 파일에 덮어쓰면 뒤 단계가 앞 단계를
# 지워서 나중에 "그때 그 SP:PTRACE 는 뭐였나" 를 못 본다 — 실제로 그렇게
# 3단계 기록을 잃었다.
start_warrant() {
	local mode=$1 phase=${2:-$1}
	LOG=$LOGDIR/$phase.log
	sudo -n rm -rf "$PIN" 2>/dev/null || die "sudo 가 만료됐다 — 다시 돌려라"
	: > "$LOG"
	# 명령을 로그에 먼저 적는다. 로그가 비는 일이 없어야 「왜 죽었는지
	# 모르겠다」가 안 나온다.
	WCTL_ARGS="-pin-dir $PIN -obj $OBJ -bind-cgroup $TCG -mode $mode \
-allow-exec $ALLOW_EXEC -allow-write $ALLOW_WRITE -deny-write $DENY_WRITE -no-color ${WCTL_EXTRA:-}"
	echo "\$ sudo -n $CTLBIN $WCTL_ARGS" >> "$LOG"
	# shellcheck disable=SC2086
	sudo -n "$CTLBIN" $WCTL_ARGS >>"$LOG" 2>&1 &
	WCTL_PID=$!
	# 수신이 시작될 때까지 기다린다. 안 기다리면 첫 프로브가 훅이 붙기 전에
	# 지나가서 "판정이 안 돈다"는 틀린 답이 나온다.
	for _ in $(seq 1 100); do
		grep -q '수신 시작' "$LOG" && return 0
		if ! kill -0 "$WCTL_PID" 2>/dev/null; then
			echo "  ── 로그 ──"; sed -n '1,40p' "$LOG" | sed 's/^/  /'
			# 백그라운드에서 죽은 이유가 로그에 안 남는 경우가 있다.
			# 같은 명령을 포그라운드로 한 번 더 돌려서 진짜 에러를 본다.
			echo "  ── 같은 명령을 포그라운드로 재현 ──"
			# shellcheck disable=SC2086
			timeout 10 sudo -n "$CTLBIN" $WCTL_ARGS 2>&1 | head -20 | sed 's/^/  /'
			echo "  (재현 종료코드 ${PIPESTATUS[0]})"
			sudo -n rm -rf "$PIN" 2>/dev/null
			die "warrantctl 이 떴다가 죽었다 (mode=$mode)"
		fi
		sleep 0.1
	done
	sed -n '1,40p' "$LOG"
	die "warrantctl 이 수신까지 못 갔다"
}

stop_warrant() {
	sudo kill -TERM "$WCTL_PID" 2>/dev/null
	wait "$WCTL_PID" 2>/dev/null
	WCTL_PID=
	sleep 0.3
}

# 이벤트 줄만 고른다. 로그 전체를 grep 하면 warrantctl 의 시작 줄
# ("cgroup 12252 -> 영장 1") 같은 것에 걸려서 아무것도 안 재고 통과한다.
# 실제로 한 번 그렇게 틀린 통과가 나왔다.
#
# 패턴은 ASCII 만 쓴다. ✓ ✗ ⚠ 는 3바이트인데 C 로케일의 grep 은 괄호식을
# 바이트 집합으로 보므로 [✓✗⚠] 가 한 글자를 못 먹는다 — 첫 바이트만 맞고
# 넘어가서 조용히 틀린 답을 낸다. 판정은 어차피 글자로도 찍힌다
# (ALLOW · DENY · OBSERVE · DRY-DENY) 므로 그걸 본다.
HOOKS='EXEC|WRITE|CREATE|UNLINK|RENAME|LINK|SYMLINK|CONNECT|FORK|SENDMSG|SP:[A-Z]+'
evts() {
	LC_ALL=C grep -E "^\[[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}\] .+ ($HOOKS) +[A-Z-]+ " "$LOG"
}
seen() { evts | LC_ALL=C grep -qE "$1"; }

# ── 3. observe — 훅이 실제로 발화하는가 ───────────────────────────
step "3. observe — 진짜 세션에서 훅이 발화하는가"

start_warrant observe 3-observe
echo "  프로그램/attach: $(grep -o '프로그램 [0-9]*개 · attach [0-9]*개' "$LOG" | head -1)"

R "$TRUE" >/dev/null 2>&1
R "$ID" >/dev/null 2>&1
R "echo x > $WORK/open/a" >/dev/null 2>&1
R "echo x > $WORK/secret/a" >/dev/null 2>&1
R "$SUDO -n $ID" >/dev/null 2>&1
sleep 0.6

# 훅 이름은 ringbuf.HookName 이 정한다 — exec 은 EXEC 이다 (BPRM 이 아니다).
if seen ' EXEC +[A-Z]'; then ok "exec 훅이 대상 세션에서 발화"; else
	no "EXEC 이 한 번도 안 찍혔다 — cgroup $TCG 태그가 exec 시점에 안 맞는다"
fi
# 태그원은 줄 끝에 찍힌다 (cg · task). 줄 끝에 못 박지 않으면 다른 데 걸린다.
if seen '[[:space:]]cg$'; then ok "1차 방어선(cgroup) 으로 태그됨"; else
	no "태그원 cg 가 없다 — session scope 가 아니라 다른 경로로 걸렸다"
fi
# observe 모드의 「막았을 것」은 OBSERVE 로 찍힌다 (VerdictName 이 모드를
# 같이 보기 때문). DENY 가 아니라 OBSERVE 를 찾아야 한다.
if seen ' +OBSERVE '; then ok "허용 밖 행위가 would-deny(OBSERVE) 로 기록됨"; else
	no "OBSERVE 판정이 없다 — observe 인데 판정이 안 났거나 전부 허용으로 샜다"
fi
if seen ' EXEC +OBSERVE '; then ok "허용 밖 exec 이 would-deny 로 판정됨"; else
	no "EXEC OBSERVE 가 없다 — exec 게이트가 판정을 안 했다"
fi
if seen ' EXEC +ALLOW '; then ok "허용 목록 exec 은 allow 로 판정됨"; else
	no "EXEC ALLOW 가 없다 — 허용 목록 inode 가 안 맞는다 (심볼릭 링크?)"
fi

# sudo 를 넘어도 태그가 유지되는가. uid 는 바뀌고 cgroup 은 그대로다.
#
# 대상 세션에는 tty 가 없어서 sudo 가 암호를 못 받는다. 그래서 먼저
# 무암호 sudo 가 되는지 보고, 안 되면 「측정 안 됨」으로 적는다 —
# 암호 때문에 sudo 가 안 돈 것을 「태그가 끊겼다」로 읽으면 안 된다.
if R "$SUDO -n true" >/dev/null 2>&1; then
	if seen 'uid1000.?→.?0|uid0'; then ok "sudo 를 넘어도 같은 세션으로 기록됨"; else
		no "uid 상승 기록이 없다 — sudo 는 돌았는데 태그가 끊겼다"
	fi
else
	printf '  \033[33m측정안됨\033[0m  sudo 가 무암호가 아니다 (tty 없는 세션). '
	printf '필요하면: echo "%s ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/99-warrant-test\n' "$USER"
fi

echo "  ── 로그 일부 ──"
evts | head -14 | sed 's/^/  /'
printf '  (이벤트 %d건 · 훅별: %s)\n' "$(evts | wc -l)" \
	"$(evts | awk '{print $3}' | sort | uniq -c | awk '{printf "%s×%s ", $2, $1}')"
stop_warrant

# ── 4. 2차 방어선 — scope 를 벗어나도 따라오는가 ──────────────────
step "4. 2차 방어선 — session scope 를 벗어난 자식"

start_warrant observe 4-escape

# 반드시 fork 를 끼운다 — fork 없이 프로세스를 옮기면 task 태그가 애초에
# 안 생겨서 「태그 없음」을 재고 2차 방어선을 쟀다고 착각한다 (지난번 실수).
#
# cgroup 이동은 조종석에서 한다. 대상 세션 안에서 sudo 를 부르면 tty 가
# 없어서 암호를 못 받고 실패한다 — 그러면 탈출이 안 된 걸 2차 방어선
# 실패로 잘못 읽게 된다.
ESCAPE=$ESCAPE_CG
GO=$WORK/esc.go
PIDF=$WORK/esc.pid
rm -f "$GO" "$PIDF"
sudo mkdir -p "$ESCAPE" 2>/dev/null || true

# 세션 안에서 자식을 하나 띄워 두고 신호를 기다리게 한다.
# 이 자식은 태그된 셸이 fork 한 것이므로 task 태그를 들고 있다.
#
# 루프에 상한을 둔다 (10초). 상한이 없으면 스크립트가 중간에 죽을 때 이
# 자식이 영원히 남고, 그게 session scope 밖에 있으면 logind 가 그 세션을
# 영원히 closing 으로 둔다 — systemd job 큐가 거기 막혀서 새 ssh 로그인이
# 전부 멈춘다. 한 번 그 상태로 박스가 잠겨 재부팅했다.
R "sh -c 'echo \$\$ > $PIDF; i=0; while [ ! -e $GO ] && [ \$i -lt 200 ]; do sleep 0.05; i=\$((i+1)); done; [ -e $GO ] && exec $ID' >/dev/null 2>&1 &" >/dev/null 2>&1

CPID=""
for _ in $(seq 1 60); do
	[ -s "$PIDF" ] && CPID=$(cat "$PIDF") && break
	sleep 0.1
done

if [ -z "$CPID" ] || ! kill -0 "$CPID" 2>/dev/null; then
	no "세션 안에 자식을 못 띄웠다 — 이 케이스는 측정 안 됨"
else
	before=$(cut -d: -f3 "/proc/$CPID/cgroup" 2>/dev/null)
	echo "$CPID" | sudo tee "$ESCAPE/cgroup.procs" >/dev/null 2>&1
	after=$(cut -d: -f3 "/proc/$CPID/cgroup" 2>/dev/null)
	echo "  자식 $CPID: $before -> $after"

	if [ "$after" = "$before" ] || [ -z "$after" ]; then
		# 탈출이 안 됐으면 이 케이스는 아무것도 재지 않았다.
		no "cgroup 탈출이 안 됐다 ($after) — 2차 방어선은 측정 안 됨"
		kill "$CPID" 2>/dev/null
	else
		ok "자식이 session scope 를 벗어났다"
		: > "$GO"          # 이제 exec 한다. cgroup 은 이미 영장 밖이다.
		sleep 0.8
		if seen '[[:space:]]task$'; then
			ok "scope 를 벗어난 자식이 2차 방어선(task) 에 걸림"
		else
			no "태그원 task 가 없다 — fork 상속이 안 된다"
		fi
	fi
	# 어느 경로로 왔든 자식을 거둔다. exec 까지 갔으면 이미 끝났고,
	# 안 갔으면 여기서 끝낸다.
	kill -9 "$CPID" 2>/dev/null
fi
rm -f "$GO" "$PIDF"
# cgroup 을 지우기 전에 남은 프로세스를 비운다. 비어 있지 않으면 rmdir 이
# 조용히 실패하고 cgroup 이 남는다.
sudo sh -c "xargs -r kill -9 < $ESCAPE/cgroup.procs" 2>/dev/null
sleep 0.2
sudo rmdir "$ESCAPE" 2>/dev/null
stop_warrant

# ── 5. dryrun ─────────────────────────────────────────────────────
step "5. dryrun — 막는 척만 하고 실제로는 통과하는가"

start_warrant dryrun 5-dryrun
R "$ID" >/dev/null 2>&1; rc_exec=$?
R "echo x > $WORK/secret/b" >/dev/null 2>&1; rc_write=$?
sleep 0.5

[ "$rc_exec" -eq 0 ] && ok "dryrun: 허용 밖 exec 이 실제로는 통과 (rc=0)" \
                     || no "dryrun 인데 exec 이 막혔다 (rc=$rc_exec)"
[ "$rc_write" -eq 0 ] && ok "dryrun: 금지 디렉터리 쓰기가 실제로는 통과" \
                      || no "dryrun 인데 쓰기가 막혔다 (rc=$rc_write)"
[ -s "$WORK/secret/b" ] && ok "dryrun: 파일이 실제로 생겼다" \
                        || no "dryrun 인데 파일이 안 생겼다"
stop_warrant

# ── 6. enforce ────────────────────────────────────────────────────
if [ "$DO_ENFORCE" -eq 0 ]; then
	step "6. enforce — 건너뜀 (--enforce 로 켠다)"
	exit 0
fi

step "6. enforce — 실제로 막히는가"

# 대상 세션은 ssh 로 만든 것이라 잠겨도 버리면 된다. 조종석은 영장 밖이다.
# 새 로그인은 새 cgroup 이라 항상 깨끗하다 — 영구 잠김은 없다.
start_warrant enforce 6-enforce

R "$TRUE" >/dev/null 2>&1; rc_allow=$?
R "$ID"   >/dev/null 2>&1; rc_deny=$?
R "echo x > $WORK/open/c"   >/dev/null 2>&1; rc_wok=$?
R "echo x > $WORK/secret/c" >/dev/null 2>&1; rc_wno=$?
sleep 0.5

[ "$rc_allow" -eq 0 ] && ok "허용 목록 바이너리는 돈다 (true rc=0)" \
                      || no "허용했는데 막혔다 (true rc=$rc_allow) — 허용 목록 inode 가 틀렸다"
[ "$rc_deny" -ne 0 ] && ok "허용 밖 바이너리는 막힌다 (id rc=$rc_deny)" \
                     || no "허용 밖인데 돌았다 (id rc=0) — exec 게이트가 안 걸렸다"
[ "$rc_wok" -eq 0 ] && ok "허용 디렉터리 쓰기는 된다" \
                    || no "허용 디렉터리인데 쓰기가 막혔다 (rc=$rc_wok)"
[ "$rc_wno" -ne 0 ] && ok "금지 디렉터리 쓰기는 막힌다 (rc=$rc_wno)" \
                    || no "금지인데 쓰기가 됐다 (rc=0)"
[ ! -s "$WORK/secret/c" ] && ok "금지 디렉터리에 파일이 안 생겼다" \
                          || no "금지인데 파일이 생겼다"

echo "  ── 로그 일부 ──"
evts | LC_ALL=C grep -E ' +DENY ' | head -10 | sed 's/^/  /'
stop_warrant

# ── 7. 자기보호의 범위 — 상대가 있는 훅 ───────────────────────────
step "7. 자기보호가 같은 영장 안까지 막는가 (ptrace · kill)"

# selfprotect() 는 상대를 안 본다 — 영장 세션이면 무조건 거부다. 그게
# bpf·umount·module_request 에서는 맞지만 상대가 있는 두 훅에서는 너무 넓다:
#
#   ptrace_access_check  ptrace 뿐 아니라 /proc/<pid>/{maps,environ,exe} 처럼
#                        PTRACE_MODE_READ 를 요구하는 읽기에도 발화한다.
#                        무조건 거부하면 sudo 가 부모를 못 읽어 깨진다.
#   task_kill            자기 자식도 못 죽인다. Ctrl-C · kill %1 이 안 된다.
#
# 그래서 네 칸을 전부 잰다. 안쪽만 재면 「안 막힌다」로 고쳤는지 「구멍을
# 열었는지」 구분이 안 된다.
#
#        | 영장 안(같은 세션)        | 영장 밖(조종석 세션)
#   ptrace  열려야 한다               막혀야 한다
#   kill    되어야 한다               막혀야 한다
#
# kill -0 도 security_task_kill 을 탄다 (check_kill_permission). 아무것도
# 죽이지 않으므로 프로브로 안전하다.

# 영장 밖 대상 — 조종석 세션에서 띄운다. 태그가 없고 uid 는 같으므로
# DAC 로는 접근 가능하고, 막힌다면 그건 우리 훅이다.
sleep 60 >/dev/null 2>&1 &
OUT_PID=$!

probe7() {
	R "sleep 30 >/dev/null 2>&1 &
	   p=\$!
	   if read -r _ < /proc/\$p/maps 2>/dev/null; then a=OPEN; else a=BLOCKED; fi
	   if read -r _ < /proc/$OUT_PID/maps 2>/dev/null; then b=OPEN; else b=BLOCKED; fi
	   if kill -0 \$p 2>/dev/null; then c=OK; else c=FAIL; fi
	   if kill -0 $OUT_PID 2>/dev/null; then d=OK; else d=FAIL; fi
	   kill \$p 2>/dev/null
	   echo \"\$a \$b \$c \$d\"" 2>/dev/null | tr -d '\r' | tail -1
}

if ! kill -0 "$OUT_PID" 2>/dev/null; then
	no "영장 밖 대상을 못 띄웠다 — 7단계는 측정 안 됨"
else
	start_warrant observe 7-observe
	read -r o_in o_out o_kin o_kout <<<"$(probe7)"; sleep 0.5
	o_rec=no; seen ' SP:PTRACE +OBSERVE ' && o_rec=yes
	o_krec=no; seen ' SP:KILL +OBSERVE ' && o_krec=yes
	stop_warrant

	start_warrant enforce 7-enforce
	read -r e_in e_out e_kin e_kout <<<"$(probe7)"; sleep 0.5
	e_rec=no; seen ' SP:PTRACE +DENY ' && e_rec=yes
	e_krec=no; seen ' SP:KILL +DENY ' && e_krec=yes
	stop_warrant

	printf '  %-28s %-18s %s\n' "" "observe" "enforce"
	printf '  %-28s %-18s %s\n' "ptrace 영장 안 (열려야)"  "$o_in"   "$e_in"
	printf '  %-28s %-18s %s\n' "ptrace 영장 밖 (막혀야)"  "$o_out"  "$e_out"
	printf '  %-28s %-18s %s\n' "kill   영장 안 (되어야)"  "$o_kin"  "$e_kin"
	printf '  %-28s %-18s %s\n' "kill   영장 밖 (막혀야)"  "$o_kout" "$e_kout"
	printf '  기록 — SP:PTRACE observe:%s enforce:%s · SP:KILL observe:%s enforce:%s\n' \
		"$o_rec" "$e_rec" "$o_krec" "$e_krec"

	# 프로브가 훅을 타는지 먼저. 안 타면 아무것도 안 쟀다 —
	# 지금까지 헛돈 네 번이 전부 이 구분을 안 해서였다.
	if [ "$o_in" != "OPEN" ] || [ "$o_kin" != "OK" ]; then
		no "observe 에서도 막혔다 (안:$o_in/$o_kin) — 프로브가 깨졌다. 7단계 버림"
	elif [ "$o_rec" = "no" ]; then
		no "observe 에 SP:PTRACE 기록이 없다 — 프로브가 그 훅을 안 탔다. ptrace 결과 버림"
	else
		# ① 영장 안은 통과해야 한다
		[ "$e_in" = "OPEN" ] && ok "ptrace: 같은 영장 안은 열린다" \
		                     || no "FINDING: enforce 에서 같은 영장 안의 /proc 읽기가 막혔다 — sudo·ps 가 깨진다"
		# ② 영장 밖은 계속 막혀야 한다. 여기가 「고쳤다」와 「구멍을 열었다」를 가른다
		if [ "$e_out" = "BLOCKED" ]; then
			ok "ptrace: 영장 밖은 막힌다 (자기보호 유지)"
		else
			no "REGRESSION: 영장 밖 /proc 읽기가 열렸다 ($e_out) — 자기보호가 뚫렸다"
		fi
	fi

	if [ "$o_krec" = "no" ]; then
		no "observe 에 SP:KILL 기록이 없다 — 프로브가 그 훅을 안 탔다. kill 결과 버림"
	else
		[ "$e_kin" = "OK" ] && ok "kill: 같은 영장 안은 보낼 수 있다" \
		                    || no "FINDING: enforce 에서 자기 자식한테 신호를 못 보낸다 — Ctrl-C 가 안 된다"
		if [ "$e_kout" = "FAIL" ]; then
			ok "kill: 영장 밖은 막힌다 (자기보호 유지)"
		else
			no "REGRESSION: 영장 밖으로 신호가 나갔다 ($e_kout) — 자기보호가 뚫렸다"
		fi
	fi
fi
kill "$OUT_PID" 2>/dev/null

# ── 8. connect 없는 UDP (§18 의 구멍) ─────────────────────────────
step "8. connect 없는 UDP 가 판정되는가"

# 핵심은 connect 를 안 하고 sendto 로 바로 보내는 것이다. bash 의 /dev/udp 는
# 내부에서 connect 를 하므로 socket_connect 로 가버리고 이 훅을 안 탄다 —
# 그걸로 재면 아무것도 안 잰다. python3 의 sendto 가 진짜 비연결 송신이다.
#
# 목적지는 127.0.0.1:9 다. 8.8.8.8 로 보내면 VM 에 경로가 없을 때
# ENETUNREACH 로 실패하는데, 그걸 「막혔다」로 읽게 된다.
#
# 세 가지를 잰다. 가운데가 본론이고 양쪽은 그게 진짜인지 받쳐준다.
#   ① inspect_udp 꺼짐  → 통과해야 한다 (기본이 꺼짐이고, 프로브가 돈다는 증거)
#   ② inspect_udp 켜짐 · 규칙 없음 → 막혀야 한다 (구멍이 닫혔다)
#   ③ inspect_udp 켜짐 · 규칙 허용 → 통과해야 한다 (전면 차단이 아니다)
udp_probe() {
	R "$PY -c 'import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b\"x\", (\"127.0.0.1\", 9))'" >/dev/null 2>&1
	echo $?
}

if [ -z "$PY" ]; then
	printf '  \033[33m측정안됨\033[0m  python3 가 없다. bash /dev/udp 는 connect 를 해서 이 훅을 안 탄다\n'
else
	WCTL_EXTRA=""
	start_warrant enforce 8-udp-off
	rc_off=$(udp_probe); sleep 0.4
	rec_off=no; seen ' SENDMSG ' && rec_off=yes
	stop_warrant

	WCTL_EXTRA="-inspect-udp"
	start_warrant enforce 8-udp-on
	rc_on=$(udp_probe); sleep 0.4
	rec_on=no; seen ' SENDMSG +DENY ' && rec_on=yes
	stop_warrant

	WCTL_EXTRA="-inspect-udp -allow-net 127.0.0.1/32"
	start_warrant enforce 8-udp-allow
	rc_allow=$(udp_probe); sleep 0.4
	stop_warrant
	WCTL_EXTRA=""

	printf '  %-34s rc=%s  SENDMSG 기록=%s\n' "① inspect_udp 꺼짐 (통과해야)" "$rc_off"   "$rec_off"
	printf '  %-34s rc=%s  SENDMSG DENY=%s\n'  "② 켜짐 · 규칙 없음 (막혀야)"   "$rc_on"    "$rec_on"
	printf '  %-34s rc=%s\n'                   "③ 켜짐 · 규칙 허용 (통과해야)" "$rc_allow"

	# 프로브가 애초에 도는지부터. 안 돌면 뒤의 판정이 전부 무의미하다.
	if [ "$rc_off" -ne 0 ]; then
		no "inspect_udp 가 꺼졌는데도 실패했다 (rc=$rc_off) — 프로브가 깨졌다. 8단계 버림"
	elif [ "$rec_off" = "yes" ]; then
		no "inspect_udp 가 꺼졌는데 SENDMSG 가 찍혔다 — 기본 꺼짐이 안 지켜진다"
	else
		ok "inspect_udp 가 꺼져 있으면 판정하지 않는다 (기본값)"

		[ "$rc_on" -ne 0 ] && ok "켜면 connect 없는 UDP 가 막힌다 (rc=$rc_on)" \
		                   || no "FINDING: 켰는데 통과했다 — §18 구멍이 그대로다"
		[ "$rec_on" = "yes" ] && ok "SENDMSG DENY 가 기록된다" \
		                      || no "차단은 됐는데 기록이 없다 — 훅이 아니라 다른 이유로 막혔을 수 있다"
		[ "$rc_allow" -eq 0 ] && ok "규칙으로 허용하면 통과한다" \
		                      || no "허용 규칙이 있는데 막혔다 (rc=$rc_allow) — UDP 는 전면 차단이 아니어야 한다"
	fi
fi

# ── 9. 감사 미러 — 두 경로의 판정이 같은가 ────────────────────────
step "9. 감사 미러 — lsm 과 kprobe 의 판정이 같은가"

# 미러의 존재 이유는 §15 의 「감사 모드와 강제 모드가 판정 함수를 공유한다」를
# 구조가 아니라 실측으로 받치는 것이다. 붙었다는 것과 판정이 같다는 것은
# 다르므로, 여기서는 세 가지를 잰다.
#   ① 미러가 전부 붙었는가 (warrantctl 이 못 붙은 것을 경고로 찍는다)
#   ② 미러가 실제로 발화했는가 (kprobe origin 기록이 있는가)
#   ③ 두 경로의 판정이 갈리지 않았는가
#
# ②가 없으면 ③은 아무것도 안 잰 것이다 — 비교할 짝이 없으면 불일치도 없다.
WCTL_EXTRA="-mirror"
start_warrant observe 9-mirror

R "$TRUE" >/dev/null 2>&1                      # EXEC
R "$ID" >/dev/null 2>&1                        # EXEC (허용 밖)
# 금지 디렉터리에서 해야 한다. inode_verdict 는 차단일 때만 기록하므로
# (§13 절제), 허용된 곳에서 지우면 훅은 지나가도 남는 게 없다 —
# 그걸 「미러가 안 돈다」로 읽으면 틀린 실패다.
# 금지 디렉터리에서 해야 한다. inode_verdict 는 차단일 때만 기록하므로,
# 허용된 곳에서 지우면 훅은 지나가도 남는 게 없다. 그걸 "미러가 안 돈다"로
# 읽으면 틀린 실패다 (실제로 한 번 그렇게 읽었다).
R "echo x > $WORK/secret/m" >/dev/null 2>&1    # CREATE · WRITE (차단 기록)
R "rm -f $WORK/secret/m" >/dev/null 2>&1       # UNLINK (차단 기록)
[ -n "$PY" ] && R "$PY -c 'import socket
try: socket.create_connection((\"127.0.0.1\", 9), 0.3)
except OSError: pass'" >/dev/null 2>&1          # CONNECT
sleep 0.8
WCTL_EXTRA=""

if grep -q '미러 미부착' "$LOG"; then
	no "미러가 안 붙었다: $(grep -o '미러 미부착.*' "$LOG" | head -2 | tr '\n' ' ')"
else
	ok "감사 미러 4종이 전부 붙었다"
fi

n_kp=$(evts | LC_ALL=C grep -c 'kprobe$' || true)
n_lsm=$(evts | LC_ALL=C grep -c 'lsm$' || true)
printf '  기록 — lsm %s건 · kprobe %s건\n' "$n_lsm" "$n_kp"
evts | LC_ALL=C grep 'kprobe$' | head -4 | sed 's/^/  /'

if [ "${n_kp:-0}" -eq 0 ]; then
	no "kprobe origin 기록이 하나도 없다 — 미러가 안 돈다. 9단계 버림"
else
	ok "미러가 실제로 발화했다 (kprobe 기록 ${n_kp}건)"

	# 훅별로도 본다. EXEC 가 안 보이면 bprm 미러만 안 도는 것이다.
	for h in EXEC UNLINK; do
		seen " $h .*kprobe\$" && ok "$h 미러 발화" \
		                     || no "$h 의 kprobe 기록이 없다"
	done

	if grep -q '판정 불일치' "$LOG"; then
		no "FINDING: $(grep -o '판정 불일치.*' "$LOG" | head -1)"
	else
		ok "lsm 과 kprobe 의 판정이 갈리지 않았다 (§15)"
	fi
fi
stop_warrant
