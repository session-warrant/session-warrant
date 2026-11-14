#!/usr/bin/env bash
# 영장 세션 하나에서 부하를 쏘고, 커널 판정 기록이 서버 DB 까지 빠짐없이 왔는지 판정한다.
#
#   SSH 세션(영장 결속) → 커널 판정 → ringbuf → warrantd → 감사 스트림 → 서버 → audit_event
#
# 맥에서 돈다. 노드에는 ssh 로, DB 에는 compose 의 PostgreSQL 컨테이너로 붙는다.
# 키를 노드에 넣지 않는다 — 이미 authorized_keys 에 있는 키와, 그 키에 결속된 살아 있는 영장이 있어야 한다.
#
#   ./audit-load.sh                       # Lima VM sw, Lima 키, 3분
#   ./audit-load.sh --duration 30         # 짧게
#   ./audit-load.sh --key ~/.ssh/id_x --user ops --host lima-sw
#
# 옵션 (괄호는 기본값)
#   --duration 초 (180)          부하 시간. 영장이 이 시간 + 30초 뒤까지 살아 있어야 한다
#   --interval 초 (0.5)          한 회 사이 쉬는 시간
#   --host 이름 (lima-sw)        ssh 대상. --ssh-config 안의 Host 이름
#   --ssh-config 경로 (~/.lima/sw/ssh.config)
#   --user 계정 ($USER)          노드 로그인 계정 = 영장의 login_account
#   --key 개인키 (ssh 설정의 첫 키)  영장에 결속된 키. 지문을 .pub 에서 읽는다
#   --node 이름 (lima-sw)        영장 대상 호스트 = 서버 node.hostname
#   --dir 경로 (~/sw-e2e)        쓰기 대상. 정책이 쓰기를 허용하지 않는 곳이어야 쓰기 기록이 남는다
#   --connect 주소/포트 (1.1.1.1/80)
#   --db-container 이름 (session-warrant-postgres-1)
#
# 결과는 out/<타임스탬프>.txt. 사전 조건 · 판정 기준은 README.md.
# 종료 코드: 0 통과 · 1 기록이 모자람 · 2 사전 조건(영장 · 접속) 실패
set -euo pipefail

DURATION=180
INTERVAL=0.5
HOST=lima-sw
NODE=lima-sw
SSH_CONFIG="$HOME/.lima/sw/ssh.config"
SSH_USER="$USER"
KEY=""
WRITE_DIR='~/sw-e2e'          # 정책이 쓰기를 허용하지 않는 곳이어야 쓰기 기록이 남는다
CONNECT=1.1.1.1/80            # 허용이든 차단이든 접속은 기록된다
DB_CONTAINER=session-warrant-postgres-1
SETTLE=60                     # 부하가 끝난 뒤 업로드를 기다리는 최대 초

usage() { sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --duration) DURATION=$2; shift 2 ;;
    --interval) INTERVAL=$2; shift 2 ;;
    --host) HOST=$2; shift 2 ;;
    --node) NODE=$2; shift 2 ;;
    --ssh-config) SSH_CONFIG=$2; shift 2 ;;
    --user) SSH_USER=$2; shift 2 ;;
    --key) KEY=$2; shift 2 ;;
    --dir) WRITE_DIR=$2; shift 2 ;;
    --connect) CONNECT=$2; shift 2 ;;
    --db-container) DB_CONTAINER=$2; shift 2 ;;
    -h|--help) usage 0 ;;
    *) echo "unknown option: $1" >&2; usage 2 ;;
  esac
done

OUT_DIR="$(cd "$(dirname "$0")" && pwd)/out"
TS=$(date +%Y%m%d-%H%M%S)
LOG="$OUT_DIR/$TS.txt"
mkdir -p "$OUT_DIR"
exec > >(tee "$LOG") 2>&1

die() { echo "✘ $*"; exit 2; }
q() { docker exec -i "$DB_CONTAINER" psql -U warrant -d warrant -tAqX -v ON_ERROR_STOP=1 -c "$1"; }

# A fresh connection every time: a reused ControlMaster connection opens no new PAM session, so no warrant binds.
SSH=(ssh -T -F "$SSH_CONFIG" -o ControlMaster=no -o ControlPath=none -o BatchMode=yes -l "$SSH_USER")
if [ -n "$KEY" ]; then
  SSH+=(-o IdentitiesOnly=yes -i "$KEY")
  PUB="$KEY.pub"
else
  PUB="$(ssh -T -G -F "$SSH_CONFIG" "$HOST" </dev/null 2>/dev/null | awk '/^identityfile /{print $2}' | sed "s|^~|$HOME|" | while read -r f; do [ -f "$f.pub" ] && { echo "$f.pub"; break; }; done)"
fi
[ -f "${PUB:-}" ] || die "공개키를 찾을 수 없다 — --key 로 개인키 경로를 준다"
FP=$(ssh-keygen -lf "$PUB" | awk '{print $2}')

echo "== 사전 조건 · $(date '+%F %T')"
echo "노드 $NODE · 계정 $SSH_USER · 키 $FP · ${DURATION}s"
docker exec "$DB_CONTAINER" true 2>/dev/null || die "DB 컨테이너 $DB_CONTAINER 가 없다 — server/ 에서 docker compose up"

# The warrant must outlive the load plus the upload wait, or the tail of the load runs unwarranted.
W=$(q "select w.display_id || ' ' || w.mode || ' ' || to_char(w.expires_at at time zone 'Asia/Seoul', 'HH24:MI:SS')
       from warrant w
       join warrant_ssh_key k on k.warrant_id = w.id
       join warrant_target_host h on h.warrant_id = w.id
       where k.fingerprint = '$FP' and h.hostname = '$NODE' and w.login_account = '$SSH_USER'
         and w.state = 'ISSUED' and not w.revoked
         and w.expires_at > now() + make_interval(secs => $DURATION + 30)
       order by w.expires_at desc limit 1")
[ -n "$W" ] || die "이 키 · 계정 · 노드에 결속된 영장이 없거나 ${DURATION}s 안에 만료된다 — 콘솔에서 신청 · 승인한다"
read -r WID WMODE WEXP <<<"$W"
# Enforce mode would actually fail the writes, so the load would not run as designed. This is an audit-mode test.
[ "$WMODE" != 2 ] || die "$WID 는 ENFORCE 다 — 감사 모드(OBSERVE · DRYRUN) 영장으로 시험한다"
echo "영장 $WID (mode $WMODE, 만료 $WEXP)"

echo "== 부하"
REMOTE=$(cat <<EOF
set -u
cg=\$(cut -d: -f3 /proc/self/cgroup)
echo "cgroup=\$(stat -c %i /sys/fs/cgroup\$cg) \$cg"
dir=$WRITE_DIR/\$\$
mkdir -p \$dir
trap 'rm -rf \$dir' EXIT
echo "start=\$(date +%s)"
end=\$((SECONDS + $DURATION)); i=0
while [ \$SECONDS -lt \$end ]; do
  i=\$((i + 1))
  ls /tmp >/dev/null
  touch \$dir/f\$i && mv \$dir/f\$i \$dir/g\$i && rm -f \$dir/g\$i
  timeout 1 bash -c 'echo > /dev/tcp/${CONNECT%/*}/${CONNECT#*/}' 2>/dev/null
  sleep $INTERVAL
done
echo "end=\$(date +%s)"
echo "rounds=\$i"
EOF
)
RES=$("${SSH[@]}" "$HOST" bash -s <<<"$REMOTE") || die "ssh 실패 — 키가 노드 authorized_keys 에 있는지 본다"
echo "$RES"
CG=$(sed -n 's/^cgroup=\([0-9]*\).*/\1/p' <<<"$RES")
START=$(sed -n 's/^start=//p' <<<"$RES")
END=$(sed -n 's/^end=//p' <<<"$RES")
ROUNDS=$(sed -n 's/^rounds=//p' <<<"$RES")
[ -n "$CG" ] && [ -n "$ROUNDS" ] || die "원격 출력을 읽지 못했다"

# Kernel verdicts of this session only: its cgroup id is never reused.
COUNTS="select
  count(*) filter (where type = 'EXEC'),
  count(*) filter (where type = 'FILE_WRITE'   and verdict in (1, 2)),
  count(*) filter (where type = 'INODE_MUTATE' and verdict in (1, 2)),
  count(*) filter (where type = 'CONNECT')
  from audit_event where cgroup_id = $CG and origin = 1"

echo "== 업로드 대기 (최대 ${SETTLE}s)"
prev=""; stable=0; waited=0
while [ $waited -lt "$SETTLE" ]; do
  cur=$(q "$COUNTS")
  if [ "$cur" = "$prev" ]; then stable=$((stable + 1)); else stable=0; fi
  [ $stable -ge 2 ] && break
  prev=$cur; sleep 2; waited=$((waited + 2))
done
IFS='|' read -r EXEC WRITE INODE CONN <<<"$cur"

GAPS=$(q "select count(*) from audit_gap g join node n on n.id = g.node_id
          where n.hostname = '$NODE' and g.to_at >= to_timestamp($START) and g.from_at <= to_timestamp($END + $SETTLE)")

# Per round: ls · touch · mv · rm · timeout · bash · sleep are 7 execs; touch opens for write;
# create · rename · unlink mutate the directory; one connect. Allowed writes are not recorded (§14), hence `--dir`.
fail=0
check() { # name actual minimum
  if [ "$2" -ge "$3" ]; then printf '✔ %-14s %6s  (≥ %s)\n' "$1" "$2" "$3"
  else printf '✘ %-14s %6s  (≥ %s)\n' "$1" "$2" "$3"; fail=1; fi
}
echo "== 판정 · cgroup $CG · $ROUNDS 회"
check "실행"            "$EXEC"  $((ROUNDS * 7))
check "쓰기(차단)"      "$WRITE" "$ROUNDS"
check "이름·삭제(차단)" "$INODE" $((ROUNDS * 3))
check "접속"            "$CONN"  "$ROUNDS"
if [ "$GAPS" -eq 0 ]; then echo "✔ 유실 구간         0"; else echo "✘ 유실 구간    $GAPS"; fail=1; fi

echo "== 결과: $([ $fail -eq 0 ] && echo 통과 || echo 실패) · $LOG"
exit $fail
