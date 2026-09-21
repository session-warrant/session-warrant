# §04 우회 경로 테스트 공통 헬퍼.
#
# warrantd 가 아직 없으므로 bats 프로세스 자신의 cgroup 을 태그해 "영장 세션"을
# 흉내 낸다 (session-N.scope 와 성질이 같다). 진짜 세션 재확인 때 이 파일만 갈아끼운다.

PROBE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROBE="$PROBE_DIR/tagprobe"
DAEMON_LOG="${BATS_FILE_TMPDIR:-/tmp}/tagprobe.log"

current_cgroup_id() {
    local cg
    cg=$(awk -F: '$1=="0"{print $3}' /proc/self/cgroup)
    stat -c %i "/sys/fs/cgroup${cg}"
}

start_probe() {
    [[ -x $PROBE ]] || { echo "tagprobe 가 없다. make" >&2; return 1; }
    mount | grep -q 'type bpf' || mount -t bpf bpf /sys/fs/bpf 2>/dev/null

    ( cd "$PROBE_DIR" && ./tagprobe daemon --tag-cgroup "$(current_cgroup_id)" ) \
        >"$DAEMON_LOG" 2>&1 &
    PROBE_PID=$!
    export PROBE_PID

    local i
    for i in $(seq 100); do
        grep -q '^READY' "$DAEMON_LOG" 2>/dev/null && return 0
        kill -0 "$PROBE_PID" 2>/dev/null || { cat "$DAEMON_LOG" >&2; return 1; }
        sleep 0.1
    done
    cat "$DAEMON_LOG" >&2
    return 1
}

stop_probe() {
    [[ -n ${PROBE_PID:-} ]] || return 0
    kill -INT "$PROBE_PID" 2>/dev/null || true
    wait "$PROBE_PID" 2>/dev/null || true
}

# 마커로 pid 를 찾는다. sudo · su · systemd-run 은 중간에 프로세스가
# 갈리므로 $! 를 믿을 수 없다. sleep 시간을 케이스마다 다르게 줘서
# 그 자체를 마커로 쓴다.
pid_of() {
    local marker=$1 i
    for i in $(seq 40); do
        local p
        p=$(pgrep -n -f -- "$marker" 2>/dev/null | head -1)
        [[ -n $p ]] && { echo "$p"; return 0; }
        sleep 0.05
    done
    return 1
}

probe_query() { "$PROBE" query "$1" 2>/dev/null; }

field() { sed -n "s/.*\b$2=\([^ ]*\).*/\1/p" <<< "$1"; }

# assert_tag <pid> <cg: yes|no> <task: yes|no>
# 두 열을 따로 봐야 systemd-run --scope 가 1차에 걸렸는지 2차에 걸렸는지 구분된다.
assert_tag() {
    local pid=$1 want_cg=$2 want_task=$3
    local out; out=$(probe_query "$pid")
    [[ -n $out ]] || { echo "pid=$pid 기록 없음 (exec 을 안 했나?)" >&2; return 1; }

    local cg task
    cg=$(field "$out" cg_tag); task=$(field "$out" task_tag)
    local got_cg=no got_task=no
    [[ ${cg:-0} != 0 ]] && got_cg=yes
    [[ ${task:-0} != 0 ]] && got_task=yes

    if [[ $got_cg != "$want_cg" || $got_task != "$want_task" ]]; then
        echo "기대: cgroup=$want_cg fork=$want_task" >&2
        echo "실제: cgroup=$got_cg fork=$got_task" >&2
        echo "  $out" >&2
        return 1
    fi
}

kill_marker() { pkill -f -- "$1" 2>/dev/null || true; }
