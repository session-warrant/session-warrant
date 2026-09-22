#!/usr/bin/env bash
# S1 — file_open 오버헤드 4단 측정
#
#   sudo ./run.sh                     기본 세트
#   sudo ./run.sh --runs 20           반복 수
#   sudo ./run.sh --workloads w_find,w_build
#   sudo ./run.sh --with-apt          apt 워크로드 포함 (네트워크 의존, 참고용)
#   sudo ./run.sh --out out/2026-08-31
#   sudo ./run.sh --tiers a,d,r,i     티어 일부만 (읽기 감시만 볼 때)
#   sudo ./run.sh --watch /etc/shadow,/usr/bin/env   감시 목록 교체
#
# 4단:
#   A  훅 없음                          기준선
#   B  return 0 만                      LSM 훅 부착 자체의 비용
#   C  + f_mode & FMODE_WRITE 앞문      S0 실측 95% 가 여기서 끝난다
#   E  D 와 같은 프로그램, 영장 없음      조회 1회로 빠져나가는가
#   D  + cgroup 조회 · 맵 2회 · 시간 비교  나머지 5% 가 내는 비용
#   R  D + 읽기 감시, cgroup 먼저         읽기 열기 전부가 cgroup 조회까지 간다
#   I  D + 읽기 감시, inode 먼저          감시 대상일 때만 cgroup 을 본다
#
# E 는 gate_d 를 태그 없이 돌린 것이다 — 프로그램이 같아야 "영장 유무" 하나만 분리된다.
# R · I 는 Policy.read_watch_paths(§15) 를 넣을 수 있는가를 잰다. 비교 기준은 D 다.
#
# 매크로(워크로드 벽시계, 계측 없는 빌드)와 마이크로(훅 1회당 ns 분포, PROBE 빌드)를
# 따로 잰다. 매크로 반복 수로는 p99 를 뽑을 수 없다.

set -euo pipefail
cd "$(dirname "$0")"

RUNS=5
PASSES=4
WARMUP=3
WITH_APT=0
OUT="out/$(date +%Y%m%d-%H%M%S)"
WORKLOADS="w_find,w_git,w_build,w_untar"
TIERS="a,b,c,e,d,r,i"
# 감시 목록. 실제로 올릴 법한 비밀 파일 + 카나리아 하나.
# /usr/bin/env 는 워크로드 스크립트의 shebang 이라 매 실행 열린다 — 여기서
# watch_hit 이 0 이면 목록이 안 맞은 것이다(dev 인코딩 등). 그 R · I 숫자는 버린다.
WATCH="/etc/shadow,/etc/gshadow,/etc/sudoers,/etc/ssh/ssh_host_ed25519_key,/etc/ssh/ssh_host_rsa_key,/usr/bin/env"

while [[ $# -gt 0 ]]; do
    case $1 in
        --runs)      RUNS=$2; shift 2 ;;
        --passes)    PASSES=$2; shift 2 ;;
        --warmup)    WARMUP=$2; shift 2 ;;
        --workloads) WORKLOADS=$2; shift 2 ;;
        --tiers)     TIERS=$2; shift 2 ;;
        --watch)     WATCH=$2; shift 2 ;;
        --with-apt)  WITH_APT=1; shift ;;
        --out)       OUT=$2; shift 2 ;;
        *) echo "알 수 없는 인자: $1" >&2; exit 2 ;;
    esac
done
[[ $WITH_APT == 1 ]] && WORKLOADS="$WORKLOADS,w_apt"

die() { echo "ERROR: $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "root 로 돌려야 한다 (BPF LSM 부착)."
command -v hyperfine >/dev/null || die "hyperfine 이 없다. sudo apt install hyperfine"
grep -qw bpf /sys/kernel/security/lsm 2>/dev/null || \
    die "/sys/kernel/security/lsm 에 bpf 가 없다. sudo ../../deploy/enable-bpf-lsm.sh 후 재부팅."
[[ -x ./gate ]] || die "빌드가 안 돼 있다. make"
[[ -d fixtures/.done ]] || die "픽스처가 없다. ./fixture.sh"

mkdir -p "$OUT"

# 워크로드가 실행될 cgroup. 이걸 태그로 심어야 티어 D 가 조회 2회를 다 탄다.
# 안 심으면 전부 tag_miss 로 빠져서 "D 가 싸다"는 틀린 답이 나온다.
CG=$(awk -F: '$1=="0"{print $3}' /proc/self/cgroup)
CGID=$(stat -c %i "/sys/fs/cgroup${CG}" 2>/dev/null || echo 0)
[[ $CGID != 0 ]] || echo "경고: cgroup id 를 못 구했다 — 티어 D 는 miss 경로만 잰다" >&2

{
    echo "kernel   $(uname -r)"
    echo "lsm      $(cat /sys/kernel/security/lsm)"
    echo "cpu      $(nproc) x $(awk -F: '/model name/{print $2; exit}' /proc/cpuinfo | xargs)"
    echo "cgroup   $CG (id=$CGID)"
    echo "runs     $RUNS x $PASSES 패스 (warmup $WARMUP)"
    echo "tiers    $TIERS"
    echo "watch    $WATCH"
    echo "date     $(date -Is)"
} | tee "$OUT/env.txt"
echo

# 티어 → 오브젝트 접미사. E 는 D 와 같은 프로그램을 쓴다.
tier_obj() { case $1 in e) echo d ;; *) echo "$1" ;; esac; }
# 티어 → 심을 cgroup id. E 만 0(=태그 없음).
tier_tag() { case $1 in e) echo 0 ;; *) echo "$CGID" ;; esac; }

IFS=, read -ra TIER_LIST <<< "$TIERS"
for t in "${TIER_LIST[@]}"; do
    [[ $t =~ ^[abcedri]$ ]] || die "알 수 없는 티어: $t (a b c e d r i)"
done
WATCH_ARGS=()
IFS=, read -ra WATCH_LIST <<< "$WATCH"
for w in "${WATCH_LIST[@]}"; do WATCH_ARGS+=(--watch "$w"); done

GATE_PID=""
gate_stop() {
    [[ -n $GATE_PID ]] || return 0
    kill -INT "$GATE_PID" 2>/dev/null || true
    wait "$GATE_PID" 2>/dev/null || true
    GATE_PID=""
}
trap 'gate_stop' EXIT

# gate 를 띄우고 READY 가 나올 때까지 기다린다.
# 이걸 안 기다리면 훅이 안 붙은 구간이 첫 워크로드에 섞인다.
gate_start() {
    local obj=$1 statsfile=$2 log=$3 tag=${4:-$CGID}
    ./gate --obj "$obj" --tag-cgroup "$tag" "${WATCH_ARGS[@]}" --out "$statsfile" >"$log" 2>&1 &
    GATE_PID=$!
    for _ in $(seq 100); do
        grep -q '^READY' "$log" 2>/dev/null && return 0
        kill -0 "$GATE_PID" 2>/dev/null || { cat "$log" >&2; die "gate 가 죽었다 ($obj)"; }
        sleep 0.1
    done
    cat "$log" >&2
    die "gate READY 타임아웃 ($obj)"
}

# ── 1단계: 매크로 (워크로드 벽시계) ─────────────────────────────────
# 티어를 블록으로 몰아 돌리면 드리프트(페이지 캐시·써멀·주파수)가 통째로 티어에
# 얹힌다. 패스를 나눠 교차시키고 report.py 가 합친다.
echo "── 매크로: 워크로드 벽시계 ($PASSES 패스 x $RUNS 회, 티어 ${TIERS//,/·} 교차) ──"
IFS=, read -ra WLS <<< "$WORKLOADS"
for wl in "${WLS[@]}"; do
    [[ -x workloads/$wl.sh ]] || die "워크로드 없음: workloads/$wl.sh"
done

for p in $(seq 1 "$PASSES"); do
    # 고정 순서는 기계의 주기적 상태 변화와 정렬돼 인공물을 만든다(2차: B 가 A 보다
    # 35% 빠름). 매 패스 섞으면 어떤 주기도 특정 티어에 붙지 못한다.
    for tier in $(shuf -e "${TIER_LIST[@]}"); do
        if [[ $tier != a ]]; then
            gate_start "gate_$(tier_obj "$tier").bpf.o" \
                       "$OUT/gate_${tier}_p${p}.json" "$OUT/gate_${tier}_p${p}.log" \
                       "$(tier_tag "$tier")"
        fi
        for wl in "${WLS[@]}"; do
            echo "  패스 $p [$tier] $wl"
            hyperfine --style basic --warmup "$WARMUP" --runs "$RUNS" \
                      --export-json "$OUT/macro_${tier}_${wl}_p${p}.json" \
                      "workloads/$wl.sh" >/dev/null
        done
        gate_stop
    done
done

# ── 2단계: 마이크로 (훅 1회당 지연 분포 + dev major) ────────────────
# PROBE 빌드는 훅마다 ktime 을 두 번 부른다 — 여기 숫자를 매크로 % 로 환산하지 말 것.
# dev major 분포는 워크로드의 성질이라 워크로드마다 따로 잰다.
echo
echo "── 마이크로: 훅 지연 분포 · dev major ─────────────────────"
for tier in "${TIER_LIST[@]}"; do
    if [[ $tier == a ]]; then continue; fi   # A 는 훅이 없어 잴 게 없다
    for wl in "${WLS[@]}"; do
        echo "  [$tier] $wl"
        gate_start "gate_$(tier_obj "$tier")_probe.bpf.o" "$OUT/probe_${tier}_${wl}.json" \
                   "$OUT/probe_${tier}_${wl}.log" "$(tier_tag "$tier")"
        "workloads/$wl.sh" >/dev/null 2>&1 || true
        gate_stop
    done
done

echo
python3 report.py "$OUT" | tee "$OUT/report.txt"
# 결과가 root 소유면 git add 에서 걸린다.
# (set -e 아래에서 [[ ]] && cmd 는 조건이 거짓일 때 스크립트를 죽인다)
if [[ -n ${SUDO_USER:-} ]]; then chown -R "$SUDO_USER" "$OUT"; fi

echo
echo "결과: $OUT"
echo
echo "맥북으로 가져가기 (out/ 은 커밋 대상이다):"
echo "  git add $OUT && git commit -m \"S1 실측: $(uname -r)\" && git push"
