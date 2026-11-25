#!/usr/bin/env bash
# 중앙 서버의 감사 수집 · 조회 부하를 k6 로 재고, 적재가 실제로 일어났는지 DB 로 검산한다.
#
# 부하 자체는 k6 스크립트가 낸다 — 그냥 돌리려면 run.sh 없이도 된다:
#   k6 run -e NODES=4 ingest.js
#   k6 run -e BASIC=<계정>:<암호> read.js
# run.sh 가 더 하는 일은 사전 조건 확인 · epoch 발급 · 쓰기와 읽기 겹치기 ·
# **DB 행수로 처리량 검산** · out/ 보존이다.
#
#   ./run.sh                          노드 1대 · 30초 · 쓰기만
#   ./run.sh --nodes 8 --duration 60  노드 8대. 처리량이 안 늘면 적재가 직렬화된 것이다
#   ./run.sh --both --token "$T"      쓰기와 읽기를 겹쳐서. 읽기는 인증이 필요하다
#   ./run.sh --read-only --basic dev@example.com:<암호>
#
# 옵션 (괄호는 기본값)
#   --nodes N (1)            가짜 노드 수 = k6 VU 수. mtls 면 노드마다 인증서가 필요하다(--certs)
#   --duration 초 (30)       부하 시간
#   --batch N (100)          배치당 이벤트 수
#   --window N (4)           ack 안 된 배치를 몇 개까지 띄워 두는가
#   --scale 1,2,4,8          노드 수만 바꿔 연달아 — 같은 묶음이라 서로 비교해도 된다
#   --session-every N (20)   배치 몇 개마다 세션 이벤트 한 건. 0 이면 안 섞는다
#   --unwarranted-pct N (20) 세션 중 무영장 비율
#   --warrants 1,2,3         세션에 붙일 영장 번호. --token · --basic 이 있으면 서버에서 읽어 온다
#   --both                   읽기 부하를 같이 돌린다
#   --read-only              읽기만
#   --addr 주소 (localhost:9090)   gRPC
#   --api URL (http://localhost:8080)
#   --certs 디렉터리 (.cache/pki)  mtls 프로필일 때. --no-tls 면 평문
#   --no-tls                 평문 gRPC (mtls 프로필 없이 띄운 서버)
#   --token JWT              읽기 인증 (oidc 프로필)
#   --basic 계정:암호         읽기 인증 (dev 프로필)
#   --prefix 이름 (k6-node-) 가짜 노드 호스트 이름 앞머리
#   --db-container 이름 (session-warrant-postgres-1)
#
# 결과는 out/<타임스탬프>/ 에. 종료 코드: 0 통과 · 1 적재가 모자람 · 2 사전 조건 실패.
set -euo pipefail
cd "$(dirname "$0")"
ROOT=$(cd ../.. && pwd)

NODES=1
DURATION=30
BATCH=100
WINDOW=4
SCALE=""
SESSION_EVERY=20
UNWARRANTED_PCT=20
WARRANT_IDS=""
MODE=ingest           # ingest | both | read
ADDR=localhost:9090
API=http://localhost:8080
CERTS="$ROOT/.cache/pki"
TLS=1
TOKEN=""
BASIC=""
PREFIX=k6-node-
DB_CONTAINER=session-warrant-postgres-1

usage() { sed -n '2,37p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --nodes) NODES=$2; shift 2 ;;
    --duration) DURATION=$2; shift 2 ;;
    --batch) BATCH=$2; shift 2 ;;
    --window) WINDOW=$2; shift 2 ;;
    --scale) SCALE=$2; shift 2 ;;
    --session-every) SESSION_EVERY=$2; shift 2 ;;
    --unwarranted-pct) UNWARRANTED_PCT=$2; shift 2 ;;
    --warrants) WARRANT_IDS=$2; shift 2 ;;
    --both) MODE=both; shift ;;
    --read-only) MODE=read; shift ;;
    --addr) ADDR=$2; shift 2 ;;
    --api) API=$2; shift 2 ;;
    --certs) CERTS=$2; shift 2 ;;
    --no-tls) TLS=0; shift ;;
    --token) TOKEN=$2; shift 2 ;;
    --basic) BASIC=$2; shift 2 ;;
    --prefix) PREFIX=$2; shift 2 ;;
    --db-container) DB_CONTAINER=$2; shift 2 ;;
    -h|--help) usage 0 ;;
    *) echo "unknown option: $1" >&2; usage 2 ;;
  esac
done

fail() { echo "ERROR: $*" >&2; exit 2; }

# 실행끼리 섞어 비교하면 안 되므로, 노드 수 비교는 한 번의 호출 안에서 연달아 돌린다.
if [ -n "$SCALE" ]; then
  rest=$(printf '%s' "$*")
  for n in $(echo "$SCALE" | tr ',' ' '); do
    echo; echo "=== 노드 $n 대 ==="
    "$0" --nodes "$n" --duration "$DURATION" --batch "$BATCH" --window "$WINDOW" \
      --session-every "$SESSION_EVERY" --unwarranted-pct "$UNWARRANTED_PCT" \
      $([ -n "$WARRANT_IDS" ] && echo --warrants "$WARRANT_IDS") \
      --addr "$ADDR" --api "$API" --certs "$CERTS" --prefix "$PREFIX" \
      --db-container "$DB_CONTAINER" $([ "$TLS" = 0 ] && echo --no-tls) \
      $([ -n "$TOKEN" ] && echo --token "$TOKEN") $([ -n "$BASIC" ] && echo --basic "$BASIC") \
      $([ "$MODE" = both ] && echo --both) $([ "$MODE" = read ] && echo --read-only) || exit $?
  done
  exit 0
fi
psql() { docker exec -i "$DB_CONTAINER" psql -U warrant -d warrant -Atc "$1"; }

# ── 사전 조건 ────────────────────────────────────────────────────────
command -v k6 >/dev/null || fail "k6 가 없다 — brew install k6"
curl -fsS -m 5 "$API/actuator/health" >/dev/null || fail "서버가 $API 에 없다 — server/ 에서 ./gradlew bootRun"
docker exec "$DB_CONTAINER" true 2>/dev/null || fail "DB 컨테이너 $DB_CONTAINER 가 없다 — server/ 에서 docker compose up -d"

AUTH_MODE=$(curl -fsS -m 5 "$API/api/auth/config" | sed -n 's/.*"mode":"\([^"]*\)".*/\1/p')

if [ "$MODE" != read ]; then
  if [ "$TLS" = 1 ]; then
    [ -f "$CERTS/ca.pem" ] || fail "CA 가 $CERTS 에 없다 — deploy/pki/pki.sh ca (평문이면 --no-tls)"
    for i in $(seq 1 "$NODES"); do
      host=$(printf '%s%02d' "$PREFIX" "$i")
      [ -f "$CERTS/nodes/$host.pem" ] || fail "$host 인증서가 없다 — make certs NODES=$NODES"
    done
  fi
fi

if [ "$MODE" != ingest ] && [ -z "$TOKEN$BASIC" ]; then
  fail "읽기 부하는 인증이 필요하다. $AUTH_MODE 프로필이면 $([ "$AUTH_MODE" = oidc ] && echo --token || echo --basic) 를 준다"
fi

# 서버에 없는 영장 번호를 쓰면 대시보드가 기록이 올 때마다 전체를 다시 읽는다 —
# 들고 있던 기록이 최근 한 페이지로 갈려 막대가 사라진다. 인증이 있으면 진짜 번호를 읽어 온다.
if [ -z "$WARRANT_IDS" ] && [ -n "$TOKEN$BASIC" ]; then
  WARRANT_IDS=$(curl -fsS -m 10 $([ -n "$TOKEN" ] && echo -H "Authorization: Bearer $TOKEN") \
      $([ -n "$BASIC" ] && echo -u "$BASIC") "$API/api/warrants" 2>/dev/null \
    | python3 -c 'import sys,json;print(",".join(str(w["warrantId"]) for w in json.load(sys.stdin)[:12]))' 2>/dev/null || true)
  [ -n "$WARRANT_IDS" ] && echo "영장 번호를 서버에서 읽었다: $WARRANT_IDS"
fi

TS=$(date +%Y%m%d-%H%M%S)
OUT="out/$TS"
mkdir -p "$OUT"

# 실행마다 새로 뽑는다. 적재는 (node_id, seq_epoch, node_seq) 로 멱등이므로,
# 같은 epoch 를 다시 쓰면 서버가 전건 중복으로 걸러 「빠르게 아무것도 안 하는」 측정이 된다.
EPOCH=$(( (RANDOM << 30) + (RANDOM << 15) + RANDOM + 1 ))

{
  echo "date        $(date +%Y-%m-%dT%H:%M:%S%z)"
  echo "server      $API · $ADDR · 인증 $AUTH_MODE · gRPC $([ "$TLS" = 1 ] && echo mTLS || echo 평문)"
  echo "server ver  $(curl -fsS -m 5 "$API/actuator/health" | head -c 200)"
  echo "mode        $MODE"
  echo "nodes       $NODES · batch $BATCH · window $WINDOW · duration ${DURATION}s"
  echo "sessions    배치 ${SESSION_EVERY}개마다 1건 · 무영장 ${UNWARRANTED_PCT}%"
  echo "warrants    ${WARRANT_IDS:-없음 (서버에 없는 #9500~ 을 쓴다)}"
  echo "epoch       $EPOCH"
  echo "k6          $(k6 version 2>&1 | head -1)"
  echo "host        $(uname -mrs)"
  echo "db rows     audit_event $(psql 'select count(*) from audit_event')"
} > "$OUT/env.txt"

before=0
if [ "$MODE" != read ]; then
  before=$(psql "select count(*) from audit_event e join node n on n.id = e.node_id where n.hostname like '${PREFIX}%'")
fi

# ── 부하 ────────────────────────────────────────────────────────────
ingest_rc=0
read_rc=0

run_ingest() {
  OUT="$OUT" ADDR="$ADDR" NODES="$NODES" DURATION="$DURATION" BATCH="$BATCH" WINDOW="$WINDOW" \
    PREFIX="$PREFIX" EPOCH="$EPOCH" PKI="$([ "$TLS" = 1 ] && echo "$CERTS" || echo '')" \
    SESSION_EVERY="$SESSION_EVERY" UNWARRANTED_PCT="$UNWARRANTED_PCT" WARRANT_IDS="$WARRANT_IDS" \
    k6 run saturation.js > "$OUT/ingest.log" 2>&1 || return $?
}

run_read() {
  OUT="$OUT" API="$API" VUS=5 DURATION="$DURATION" TOKEN="$TOKEN" BASIC="$BASIC" \
    k6 run read.js > "$OUT/read.log" 2>&1 || return $?
}

case "$MODE" in
  ingest) echo "쓰기 부하 ${DURATION}초…"; run_ingest || ingest_rc=$? ;;
  read)   echo "읽기 부하 ${DURATION}초…"; run_read || read_rc=$? ;;
  both)
    echo "쓰기 · 읽기 겹쳐서 ${DURATION}초…"
    run_ingest &
    ipid=$!
    run_read &
    rpid=$!
    wait "$ipid" || ingest_rc=$?    # `cmd || rc=$? &` 로 쓰면 종료 코드가 묻힌다
    wait "$rpid" || read_rc=$?
    ;;
esac

# ── 검산 — 보낸 만큼 DB 에 들어왔는가 ──────────────────────────────
after=0
if [ "$MODE" != read ]; then
  for _ in $(seq 1 30); do   # 서버가 마지막 배치를 적재할 시간
    after=$(psql "select count(*) from audit_event e join node n on n.id = e.node_id where n.hostname like '${PREFIX}%'")
    sleep 1
    now=$(psql "select count(*) from audit_event e join node n on n.id = e.node_id where n.hostname like '${PREFIX}%'")
    [ "$now" = "$after" ] && break
  done
fi

python3 report.py "$OUT" --rows-before "$before" --rows-after "$after" --nodes "$NODES" \
  --duration "$DURATION" --mode "$MODE" | tee "$OUT/report.txt"
verdict=${PIPESTATUS[0]}

echo
echo "결과: $OUT  (커밋하지 않는다 — 판정에 쓰면 PR 본문에 요약)"
[ "$ingest_rc" = 0 ] && [ "$read_rc" = 0 ] || { echo "k6 가 0 이 아닌 코드로 끝났다 — $OUT/*.log" >&2; exit 1; }
exit "$verdict"
