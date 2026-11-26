#!/bin/bash
# wtest.sh v2 — Go 없이 커널 판정만 검증한다. bpftool 로 맵에 직접 써넣는다.
#
# 조종하는 셸(이 스크립트)은 영장 밖에 있고, 테스트는 /sys/fs/cgroup/wtest
# 안에서만 돈다. 자기보호 훅이 bpf() 를 막으므로 이 분리가 필수다.
#
# 막히면: sudo bpftool map update pinned /sys/fs/bpf/wmaps/active_flag \
#           key hex 00 00 00 00 value hex 00
# 그래도 막히면 재부팅. BPF 상태는 부팅을 못 넘는다.

set -u

OBJ=${OBJ:-bpf/warrant.bpf.o}
P=/sys/fs/bpf/wtest
M=/sys/fs/bpf/wmaps
CGDIR=/sys/fs/cgroup/wtest
CGOUT=/sys/fs/cgroup/wtest_out     # 영장 안 걸린 cgroup. 2차 태그 분리용
WID=1
POLICY=7
UID_=$(id -u)

pass=0; fail=0
ok()    { echo "  PASS  $1"; pass=$((pass+1)); }
no()    { echo "  FAIL  $1"; fail=$((fail+1)); }
head_() { echo; echo "=== $1 ==="; }

le() {   # 정수 → little-endian hex
	local v=$1 n=$2 i
	for ((i = 0; i < n; i++)); do printf '%02x ' $(((v >> (8 * i)) & 0xff)); done
}

kdev() { # 커널 s_dev = 12bit major : 20bit minor. 유저 공간 st_dev 와 다르다
	echo $((($(stat -Lc '%Hd' "$1") << 20) | $(stat -Lc '%Ld' "$1")))
}

mapput() { sudo bpftool map update pinned "$M/$1" key hex $2 value hex $3; }
# stat 은 -L 없이는 symlink 자체를 본다. 커널은 대상을 연다 — 반드시 -L.
rulekey() { echo "$(le $POLICY 4)$(le $(kdev "$1") 4)$(le $(stat -Lc '%i' "$1") 8)"; }

# rule_net 은 LPM_TRIE 다. 키 = prefixlen(4) · policy_id(4, **big-endian**) · addr[16].
# IPv4 는 ::ffff:a.b.c.d 로 펴서 넣으므로 앞 96비트가 전부 유효하다 —
# prefixlen = 32(policy) + 96(매핑 프리픽스) + CIDR 비트.
netkey() { # $1 = a.b.c.d · $2 = CIDR 비트수
	local o1 o2 o3 o4
	IFS=. read -r o1 o2 o3 o4 <<< "$1"
	printf '%s' "$(le $((128 + $2)) 4)"
	printf '%02x %02x %02x %02x ' $(((POLICY >> 24) & 0xff)) $(((POLICY >> 16) & 0xff)) \
	                              $(((POLICY >> 8) & 0xff)) $((POLICY & 0xff))
	printf '00 %.0s' $(seq 10)
	printf 'ff ff '
	printf '%02x %02x %02x %02x ' "$o1" "$o2" "$o3" "$o4"
}

# 값 = proto(1) · nports(1) · ports[7](각 2, host order). nports=0 이면 모든 포트.
netval() { # $1 = proto(0 ANY · 1 TCP · 2 UDP), 나머지 = 포트
	local proto=$1 n i; shift; n=$#
	printf '%s' "$(le $proto 1)$(le $n 1)"
	for i in "$@"; do printf '%s' "$(le $i 2)"; done
	for ((i = n; i < 7; i++)); do printf '%s' "$(le 0 2)"; done
}

# ── 0. probe 빌드 ─────────────────────────────────────────────────
# bpftool 로 자기보호를 재면 안 된다 — bpftool 이 실행 허용 목록에 없으면
# BPF 조작까지 가기도 전에 실행 단계에서 막혀 엉뚱한 결과가 나온다.
if [ ! -x /tmp/bpfprobe ]; then
	cat > /tmp/bpfprobe.c <<'PEOF'
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
int main(void) {
	union bpf_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.start_id = 0;
	int r = syscall(__NR_bpf, BPF_PROG_GET_NEXT_ID, &attr, sizeof(attr));
	if (r < 0 && errno == EPERM) { fprintf(stderr, "EPERM\n"); return 1; }
	return 0;
}
PEOF
	gcc -O2 -o /tmp/bpfprobe /tmp/bpfprobe.c || exit 1
fi

# connprobe — TCP connect 가 LSM 을 통과했는지만 본다.
#
# ECONNREFUSED 는 **통과**다. 듣는 쪽이 없다는 뜻이지 막혔다는 뜻이 아니다.
# 이 구분을 안 하면 리스너를 띄워야 하고, 그러면 리스너 자체가 실행 허용
# 목록에 들어가야 해서 재려는 것과 다른 게 섞인다.
if [ ! -x /tmp/connprobe ]; then
	cat > /tmp/connprobe.c <<'PEOF'
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(int argc, char **argv) {
	if (argc != 3) return 2;
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) return 2;
	struct sockaddr_in a;
	memset(&a, 0, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_port = htons((unsigned short)atoi(argv[2]));
	if (inet_pton(AF_INET, argv[1], &a.sin_addr) != 1) return 2;
	int r = connect(fd, (struct sockaddr *)&a, sizeof(a));
	int e = errno;
	close(fd);
	if (r == 0) return 0;
	if (e == ECONNREFUSED || e == ETIMEDOUT || e == EINPROGRESS) return 0;
	if (e == EPERM || e == EACCES) { fprintf(stderr, "EPERM\n"); return 1; }
	fprintf(stderr, "connect: %s\n", strerror(e));
	return 2;
}
PEOF
	gcc -O2 -o /tmp/connprobe /tmp/connprobe.c || exit 1
fi

# expprobe — 만료가 발효되는 시각을 잰다.
#
# touch 를 반복 호출하면 프로세스 기동(수 ms)이 재려는 값보다 커서 분해능이
# 그것에 묶인다. 한 프로세스 안에서 돌려야 만료 시각과 첫 거부의 간격이
# 보인다. 시계는 CLOCK_BOOTTIME — 커널의 bpf_ktime_get_boot_ns 와 같은 기준이다.
if [ ! -x /tmp/expprobe ]; then
	cat > /tmp/expprobe.c <<'PEOF'
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
static long long boot_ns(void) {
	struct timespec ts;
	clock_gettime(CLOCK_BOOTTIME, &ts);
	return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}
int main(int argc, char **argv) {
	if (argc != 3) return 2;
	long long deadline = boot_ns() + atoll(argv[2]);
	for (;;) {
		int fd = open(argv[1], O_WRONLY | O_CREAT, 0644);
		if (fd < 0 && (errno == EPERM || errno == EACCES)) {
			printf("%lld\n", boot_ns());
			return 0;
		}
		if (fd >= 0) close(fd);
		if (boot_ns() > deadline) return 1;   /* 시간 안에 안 막혔다 */
		struct timespec s = {0, 200000};      /* 200µs */
		nanosleep(&s, 0);
	}
}
PEOF
	gcc -O2 -o /tmp/expprobe /tmp/expprobe.c || exit 1
fi

# ── 1. 로드 · attach ──────────────────────────────────────────────
head_ "1. 로드 · attach"

sudo rm -rf "$P" "$M"
if ! sudo bpftool prog loadall "$OBJ" "$P" pinmaps "$M" autoattach 2>/tmp/wt_load.err; then
	echo "  loadall 실패:"; cat /tmp/wt_load.err; exit 1
fi
nprog=$(sudo ls "$P" | wc -l)
nlink=$(sudo bpftool link list 2>/dev/null | grep -c '^[0-9]*:')
echo "  prog $nprog · link $nlink"
[ "$nlink" -ge "$nprog" ] && ok "$nprog개 attach" || { no "attach 누락"; exit 2; }

# ── 2. 영장 주입 ──────────────────────────────────────────────────
head_ "2. 영장 주입"

sudo mkdir -p "$CGDIR" "$CGOUT"
CG=$(stat -c '%i' "$CGDIR")
echo "  영장 cgroup $CG · 영장 밖 cgroup $(stat -c '%i' "$CGOUT")"

# struct warrant (32B): expires(8) grace(8) subject(4) policy(4) revoked mode on_expiry break_glass pad(4)
warrant_bytes() {
	echo "$(le $1 8)$(le 0 8)$(le 42 4)$(le $POLICY 4)$(le $2 1)$(le 2 1)$(le 0 1)$(le $3 1)$(le 0 4)"
}
mapput warrants "$(le $WID 8)" "$(warrant_bytes 0 0 0)" || exit 1
mapput cgroup_warrant "$(le $CG 8)" "$(le $WID 8)" || exit 1

# 실행 허용. /usr/bin/id 는 일부러 뺀다 — 이게 차단 탐침이다.
# 래퍼(sudo·setsid·nohup·setpriv)를 넣어야 한다. 안 넣으면 래퍼 자체가
# 실행 단계에서 막혀서 "태그가 살아 있어서 막혔다"와 구분이 안 된다.
for b in /bin/sh /bin/bash /usr/bin/true /usr/bin/touch /usr/bin/mv \
         /usr/bin/sleep /usr/bin/cat /usr/bin/sudo /usr/bin/setsid \
         /usr/bin/nohup /usr/bin/setpriv /usr/bin/env /tmp/bpfprobe \
         /tmp/connprobe /tmp/expprobe; do
	[ -e "$b" ] && mapput rule_exec "$(rulekey $b)" "01" >/dev/null
done

# 쓰기: /tmp/wt 허용(재귀), /tmp/wt/secret 금지
sudo rm -rf /tmp/wt && mkdir -p /tmp/wt/secret /tmp/wt/sub && chmod -R 777 /tmp/wt
mapput rule_write "$(rulekey /tmp/wt)"        "$(le 1 1)$(le 1 1)$(le 0 6)" >/dev/null
mapput rule_write "$(rulekey /tmp/wt/secret)" "$(le 2 1)$(le 1 1)$(le 0 6)" >/dev/null
# 기본 허용 세트 — 이게 없으면 /dev/null 을 여는 정상 프로그램이 전부 죽는다
mapput rule_write "$(rulekey /dev/null)" "$(le 1 1)$(le 0 1)$(le 0 6)" >/dev/null
# 2차 태그 테스트가 자기를 옮길 수 있도록. cgroup 조작은 원래 통제 대상이라 막힌다
mapput rule_write "$(rulekey $CGOUT)" "$(le 1 1)$(le 1 1)$(le 0 6)" >/dev/null

ncpu=$(nproc)
if ! sudo bpftool map update pinned "$M/active_flag" key hex 00 00 00 00 value hex 01 2>/dev/null; then
	v=""; for ((i = 0; i < ncpu; i++)); do v="$v 01"; done
	sudo bpftool map update pinned "$M/active_flag" key hex 00 00 00 00 value hex $v || exit 1
fi
ok "영장 · 규칙 주입"

# ── 실행기 ────────────────────────────────────────────────────────
# 조종 셸은 절대 이 cgroup 에 들어가지 않는다.
in_cg()    { sudo sh -c 'echo $$ > '"$CGDIR"'/cgroup.procs; exec "$@"' sh "$@" >/dev/null 2>&1; }
in_cg_sh() { sudo sh -c 'echo $$ > '"$CGDIR"'/cgroup.procs; exec /bin/sh -c "$1"' sh "$1" >/dev/null 2>&1; }

allow()    { if in_cg "$@";    then ok "$T"; else no "$T (거부됨 — 허용이어야 한다)"; fi; }
deny()     { if in_cg "$@";    then no "$T (통과됨 — 거부여야 한다)"; else ok "$T"; fi; }
allow_sh() { if in_cg_sh "$1"; then ok "$T"; else no "$T (거부됨 — 허용이어야 한다)"; fi; }
deny_sh()  { if in_cg_sh "$1"; then no "$T (통과됨 — 거부여야 한다)"; else ok "$T"; fi; }

# ── 3. 실행 화이트리스트 ──────────────────────────────────────────
head_ "3. 실행 화이트리스트 (RQ2)"
T="허용된 바이너리";           allow /usr/bin/true
T="미허용 바이너리 (root)";    deny  /usr/bin/id

# ── 4. 태그 유지 ──────────────────────────────────────────────────
# 각 래퍼마다 두 번 잰다. true 가 통과해야 래퍼 자체가 안 막힌 것이고,
# 그 조건에서 id 가 막혀야 태그가 살아남은 것이다. 한쪽만 재면 구분이 안 된다.
head_ "4. 태그 유지 (RQ1)"

T="sudo 통과 — 래퍼 확인";     allow /usr/bin/sudo /usr/bin/true
T="sudo 넘어 태그 유지";       deny  /usr/bin/sudo /usr/bin/id

T="setpriv 통과 — 래퍼 확인";  allow /usr/bin/setpriv --reuid=$UID_ --regid=$UID_ --clear-groups /usr/bin/true
T="uid 바뀌어도 태그 유지";    deny  /usr/bin/setpriv --reuid=$UID_ --regid=$UID_ --clear-groups /usr/bin/id

T="setsid 통과 — 래퍼 확인";   allow /usr/bin/setsid --wait /usr/bin/true
T="setsid 넘어 태그 유지";     deny  /usr/bin/setsid --wait /usr/bin/id

T="nohup 통과 — 래퍼 확인";    allow /usr/bin/nohup /usr/bin/true
T="nohup 넘어 태그 유지";      deny  /usr/bin/nohup /usr/bin/id

T="백그라운드 통과 — 확인";     allow_sh '/usr/bin/true & wait $!'
T="백그라운드 태그 유지";       deny_sh  '/usr/bin/id & wait $!'

# 2차 방어선만 따로 잰다. fork 로 태그를 물려받은 자식을 영장 밖 cgroup 으로
# 옮긴다 — 1차(cgroup) 조회는 빗나가므로 여기서 막히면 task 태그가 잡은 것이다.
# cgroup 이동이 실패하면 exit 0 으로 빠져 "통과됨" = FAIL 로 드러난다.
# & 로 반드시 fork 를 일으킨다. 자기 자신을 cgroup 에 써넣는 방식으로는
# fork 훅이 안 불려서 task 태그가 생기지 않는다 — 그러면 2차 방어선이 아니라
# "태그가 아예 없는 상태"를 재게 된다.
esc() { echo "{ echo \$\$ > $CGOUT/cgroup.procs || exit 9; exec $1; } & wait \$!"; }
T="cgroup 벗어나도 통과 — 확인";  allow_sh "$(esc /usr/bin/true)"
T="cgroup 벗어나도 태그 유지";    deny_sh  "$(esc /usr/bin/id)"

# ── 5. 쓰기 규칙 ──────────────────────────────────────────────────
head_ "5. 쓰기 규칙"
T="허용 디렉터리";              allow /usr/bin/touch /tmp/wt/a
T="하위 디렉터리 (recursive)";  allow /usr/bin/touch /tmp/wt/sub/a
T="허용 밖";                    deny  /usr/bin/touch /tmp/outside_$$
T="금지가 허용을 이긴다";        deny  /usr/bin/touch /tmp/wt/secret/a

# ── 6. rename 우회 ────────────────────────────────────────────────
head_ "6. rename 우회 (RQ6)"
T="허용 → 금지";  deny /usr/bin/mv /tmp/wt/a /tmp/wt/secret/a
T="허용 → 밖";    deny /usr/bin/mv /tmp/wt/a /tmp/moved_$$

# ── 7. 자기보호 ───────────────────────────────────────────────────
head_ "7. 자기보호 (§16)"
T="영장 세션에서 bpf()"; deny /tmp/bpfprobe

head_ "8. 비상용 영장 (break_glass)"
mapput warrants "$(le $WID 8)" "$(warrant_bytes 0 0 1)" >/dev/null
T="break_glass 면 통과"; allow /tmp/bpfprobe
mapput warrants "$(le $WID 8)" "$(warrant_bytes 0 0 0)" >/dev/null

# ── 9. 만료 ───────────────────────────────────────────────────────
head_ "9. 만료"
NOW=$(awk '{printf "%d", $1 * 1000000000}' /proc/uptime)
mapput warrants "$(le $WID 8)" "$(warrant_bytes $((NOW + 3000000000)) 0 0)" >/dev/null
T="만료 전 쓰기"; allow /usr/bin/touch /tmp/wt/b
sleep 4
T="만료 후 쓰기";                deny  /usr/bin/touch /tmp/wt/c
T="만료 후 실행 (DEMOTE 라 통과)"; allow /usr/bin/true

# ── 10. 취소 ──────────────────────────────────────────────────────
head_ "10. 취소 (RQ3)"
mapput warrants "$(le $WID 8)" "$(warrant_bytes 0 1 0)" >/dev/null
T="취소 후 쓰기"; deny /usr/bin/touch /tmp/wt/d
T="취소 후 실행"; deny /usr/bin/true

# ── 11. 네트워크 규칙 ─────────────────────────────────────────────
#
# 규칙이 없으면 net_allowed 가 0 을 돌려주므로 아웃바운드가 전면 차단이다 (§15).
# 여기서 보는 건 「차단되더라」가 아니라 **규칙대로 갈린다**는 것이다 —
# CIDR · 포트 목록 · proto 셋이 각각 판정에 쓰이는지.
head_ "11. 네트워크 규칙"
mapput warrants "$(le $WID 8)" "$(warrant_bytes 0 0 0)" >/dev/null

T="규칙 없음 — 전면 차단"; deny /tmp/connprobe 127.0.0.1 9

# 127.0.0.1/32, TCP, 모든 포트
mapput rule_net "$(netkey 127.0.0.1 32)" "$(netval 1)" >/dev/null
T="허용 CIDR 안"; allow /tmp/connprobe 127.0.0.1 9
T="허용 CIDR 밖"; deny  /tmp/connprobe 127.0.0.2 9

# 같은 주소를 포트 목록으로 좁힌다. nports != 0 이면 목록에 있는 포트만.
mapput rule_net "$(netkey 127.0.0.1 32)" "$(netval 1 9)" >/dev/null
T="허용 포트";  allow /tmp/connprobe 127.0.0.1 9
T="비허용 포트"; deny  /tmp/connprobe 127.0.0.1 7

# proto 가 UDP 인 규칙은 TCP connect 를 허용하지 않는다.
mapput rule_net "$(netkey 127.0.0.1 32)" "$(netval 2)" >/dev/null
T="proto 불일치 (UDP 규칙 · TCP 연결)"; deny /tmp/connprobe 127.0.0.1 9

# 프리픽스가 짧아도 LPM 이 맞춘다.
sudo bpftool map delete pinned "$M/rule_net" key hex $(netkey 127.0.0.1 32) >/dev/null 2>&1
mapput rule_net "$(netkey 127.0.0.0 8)" "$(netval 0)" >/dev/null
T="짧은 프리픽스 (127.0.0.0/8)"; allow /tmp/connprobe 127.0.0.2 9
T="프리픽스 밖 (10.x)";          deny  /tmp/connprobe 10.255.255.1 9

# ── 12. 만료 지연 ─────────────────────────────────────────────────
#
# §19 가 요구하는 「만료 적용 latency」다. 커널은 판정마다
# bpf_ktime_get_boot_ns() 와 expires_ns 를 비교하므로 지연의 하한은 0 이고,
# 여기서 재는 건 **첫 거부가 만료 시각보다 얼마나 늦게 나오는가** 다.
# 그 값이 탐침의 폴링 간격(200µs) 수준이면 「세션 안에서 즉시 발효된다」가
# 측정으로 뒷받침된다.
#
# touch 를 반복하면 프로세스 기동이 재려는 값보다 커서 못 잰다 — expprobe 가
# 한 프로세스 안에서 돈다. 시계 기준이 커널과 같아야 해서 CLOCK_BOOTTIME 이다.
head_ "12. 만료 지연"
sudo rm -f /tmp/wt/exp
NOW=$(awk '{printf "%d", $1 * 1000000000}' /proc/uptime)
EXP=$((NOW + 2000000000))
mapput warrants "$(le $WID 8)" "$(warrant_bytes $EXP 0 0)" >/dev/null

# 조종 셸은 cgroup 에 안 들어간다. 탐침만 들어가서 자기 시각을 찍는다.
DENY_AT=$(sudo sh -c 'echo $$ > '"$CGDIR"'/cgroup.procs; exec /tmp/expprobe /tmp/wt/exp 6000000000' 2>/dev/null)
if [ -n "$DENY_AT" ]; then
	LAT=$((DENY_AT - EXP))
	echo "  만료 $EXP · 첫 거부 $DENY_AT"
	if [ "$LAT" -ge 0 ] && [ "$LAT" -lt 50000000 ]; then
		ok "만료 지연 ${LAT}ns ($((LAT / 1000))µs)"
	else
		no "만료 지연 ${LAT}ns — 0 이상 50ms 미만이어야 한다"
	fi
else
	no "만료 지연 — 탐침이 시간 안에 거부를 못 봤다"
fi

# ── 정리 ──────────────────────────────────────────────────────────
head_ "정리"
sudo bpftool map update pinned "$M/active_flag" key hex 00 00 00 00 value hex 00 >/dev/null 2>&1 ||
	{ v=""; for ((i = 0; i < ncpu; i++)); do v="$v 00"; done
	  sudo bpftool map update pinned "$M/active_flag" key hex 00 00 00 00 value hex $v; }
sudo rm -rf "$P" "$M" /tmp/wt
sudo rmdir "$CGDIR" "$CGOUT" 2>/dev/null
echo "  active_flag=0 · pin 제거"

echo
echo "=========================================="
echo "  PASS $pass · FAIL $fail"
echo "=========================================="
[ "$fail" -eq 0 ]
