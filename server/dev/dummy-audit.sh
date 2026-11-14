#!/usr/bin/env bash
# 로컬 DB(compose 의 PostgreSQL)에 더미 감사 기록을 넣는다 — 대시보드 「구간」을 큰 데이터로 시험하려고.
#
#   ./dummy-audit.sh seed 2      # 약 2GB (audit_event 기준). 숫자는 GB
#   ./dummy-audit.sh size        # 더미 건수 · 테이블 크기
#   ./dummy-audit.sh clean       # 더미 노드에 딸린 것만 지우고 공간을 돌려받는다
#
# 실제 기록과 섞이지 않게:
#   - 노드는 client_cert_fingerprint 가 'dummy:' 로 시작하는 4대(dummy-web-01 · dummy-web-02 · dummy-db-01 · dummy-app-01)
#   - 영장 번호는 9001~9060(서버에 없는 번호라 화면에 「#9001」로 보인다), 출발지는 문서용 주소 203.0.113.0/24
#   - received_seq 는 음수다. 대시보드는 「받은 순번 N 뒤」로 이어 받으므로 열려 있는 화면이 수백만 건을 따라잡지 않는다.
#     발생 시각으로 고르는 구간 조회 · 집계에만 잡힌다.
# 분포: 지난 30일, 78% 는 서울 시각 09~19시. 실행 33 · 쓰기 12 · 이름·삭제 15 · 접속 10 · 자기보호 0.3 · fork 30%, 그중 18% 는 kprobe 미러.
# dummy-app-01 은 ENFORCE 라 차단이 DENY, 나머지는 DRYRUN 이라 WOULD_DENY.
set -euo pipefail

DB_CONTAINER=${DB_CONTAINER:-session-warrant-postgres-1}
BATCH=${BATCH:-500000}
psql() { docker exec -i "$DB_CONTAINER" psql -U warrant -d warrant -v ON_ERROR_STOP=1 -qtA "$@"; }
dummy_bytes() { psql -c "select pg_total_relation_size('audit_event_default')"; }

nodes() {
  psql <<'SQL'
insert into node (client_cert_fingerprint, hostname, kernel_version, bpf_lsm_enabled, agent_version, current_seq_epoch, last_seen_at)
select 'dummy:' || h, h, '6.8.0-dummy', true, 'dummy', 77000 + k, now()
from (values ('dummy-app-01', 0), ('dummy-db-01', 1), ('dummy-web-01', 2), ('dummy-web-02', 3)) v(h, k)
where not exists (select 1 from node where client_cert_fingerprint = 'dummy:' || h);
SQL
}

# One batch of audit_event rows numbered [start, start + n). Every random draw is its own column so they stay independent.
batch() {
  psql -v start="$1" -v n="$2" <<'SQL'
with dn as (
  select id, (current_seq_epoch - 77000)::int as k, hostname = 'dummy-app-01' as enforce from node where client_cert_fingerprint like 'dummy:%'
), g as (
  select n, random() as r_day, random() as r_hour, random() as r_work, random() as r_type, random() as r_mirror, random() as r_allow
  from generate_series(:start::bigint, :start::bigint + :n - 1) n
), t as (
  select g.*, dn.id as node_id, dn.k, dn.enforce,
    case when r_type < 0.33 then 'EXEC' when r_type < 0.45 then 'FILE_WRITE' when r_type < 0.60 then 'INODE_MUTATE'
         when r_type < 0.70 then 'CONNECT' when r_type < 0.703 then 'SELF_PROTECTION_HIT' else 'FORK' end as type,
    (date_trunc('day', now() at time zone 'Asia/Seoul') at time zone 'Asia/Seoul') - floor(r_day * 30) * interval '1 day'
      + case when r_work < 0.78 then interval '9 hour' + r_hour * interval '10 hour' else r_hour * interval '24 hour' end as at
  from g join dn on dn.k = g.n % 4
)
insert into audit_event (occurred_at, node_id, seq_epoch, node_seq, warrant_id, kernel_subject_id, type, verdict, mode, tag_source,
                         origin, pid, cgroup_id, uid, device_id, inode, destination, hook, comm, received_seq)
select case when at > now() then at - interval '1 day' else at end,
       node_id, 77000 + k, n,
       9001 + (n / 3000) % 60, 1 + (n / 3000) % 12, type,
       case when type = 'FORK' then 0
            when type = 'EXEC' and r_allow < 0.7 then 0
            when type = 'CONNECT' and r_allow < 0.5 then 0
            when enforce then 1 else 2 end,
       case when enforce then 2 else 1 end,
       case when r_mirror > 0.97 then 2 else 1 end,
       case when type in ('EXEC', 'FILE_WRITE', 'CONNECT') and r_mirror < 0.18 then 2 else 1 end,
       2000 + n % 30000, 900000 + (n / 3000) * 4 + k, 1001 + (n / 3000) % 12,
       case when type in ('CONNECT', 'FORK') then null else 2049 end,
       case when type in ('CONNECT', 'FORK') then null else 100000 + (n * 31) % 500000 end,
       case when type = 'CONNECT' then '10.0.' || n % 8 || '.' || n % 250 || ':443' end,
       case type when 'EXEC' then 2 when 'FILE_WRITE' then 4 when 'INODE_MUTATE' then 5 + n % 3 when 'CONNECT' then 3
                 when 'SELF_PROTECTION_HIT' then 10 + n % 5 else 1 end,
       case type when 'EXEC' then (array['ls','cat','grep','systemctl','git','python3','bash','sleep','journalctl','cp'])[1 + n % 10]
                 when 'FILE_WRITE' then (array['touch','vi','cp','tee'])[1 + n % 4]
                 when 'INODE_MUTATE' then (array['mv','rm','ln'])[1 + n % 3]
                 when 'CONNECT' then (array['curl','git','ssh','apt'])[1 + n % 4]
                 when 'SELF_PROTECTION_HIT' then 'gdb' else 'bash' end,
       -n
from t;
SQL
}

# A few hundred unwarranted logins and a few dozen loss windows over the same 30 days.
extras() {
  psql <<'SQL'
with dn as (select id, (current_seq_epoch - 77000)::int as k from node where client_cert_fingerprint like 'dummy:%')
insert into unwarranted_session (node_id, observed_at, login_account, ssh_key_fingerprint, source_address, cgroup_id, reason, seq_epoch, node_seq)
select dn.id, now() - random() * interval '30 day', (array['root','ubuntu','deploy','ec2-user'])[1 + n % 4],
       case when n % 5 = 0 then null else 'SHA256:dummy' || n end, '203.0.113.' || (n % 250 + 1), 800000 + n,
       (array['NO_WARRANT','NO_WARRANT','KEY_MISMATCH','NO_KEY','AGENT_UNREACHED'])[1 + n % 5], 77100 + dn.k, n
from generate_series(1, 400) n join dn on dn.k = n % 4
on conflict do nothing;

with dn as (select id, (current_seq_epoch - 77000)::int as k from node where client_cert_fingerprint like 'dummy:%'),
w as (select n, now() - random() * interval '30 day' as f from generate_series(1, 40) n)
insert into audit_gap (node_id, from_at, to_at, dropped_count, cause)
select dn.id, w.f, w.f + (5 + n % 120) * interval '1 second', 10 + (n * 37) % 900,
       (array['RINGBUF_OVERFLOW','CPU_SEQ_SKIP','AGENT_DOWN'])[1 + n % 3]
from w join dn on dn.k = w.n % 4
on conflict do nothing;
SQL
}

case "${1:-}" in
  seed)
    GB=${2:-2}
    target=$(( $(dummy_bytes) + GB * 1024 * 1024 * 1024 ))
    nodes
    start=$(psql -c "select coalesce(max(node_seq), 0) + 1 from audit_event where node_id in (select id from node where client_cert_fingerprint like 'dummy:%')")
    while [ "$(dummy_bytes)" -lt "$target" ]; do
      t0=$SECONDS
      batch "$start" "$BATCH"
      start=$((start + BATCH))
      echo "$(date +%T) +${BATCH} rows ($((SECONDS - t0))s) · audit_event $(psql -c "select pg_size_pretty(pg_total_relation_size('audit_event_default'))")"
    done
    extras
    psql -c "analyze audit_event_default; analyze unwarranted_session; analyze audit_gap"
    "$0" size
    ;;
  size)
    psql -F ' ' <<'SQL'
select 'dummy rows', count(*) from audit_event where node_id in (select id from node where client_cert_fingerprint like 'dummy:%');
select 'audit_event', pg_size_pretty(pg_total_relation_size('audit_event_default'));
select 'database', pg_size_pretty(pg_database_size(current_database()));
SQL
    ;;
  clean)
    psql <<'SQL'
delete from audit_event where node_id in (select id from node where client_cert_fingerprint like 'dummy:%');
delete from unwarranted_session where node_id in (select id from node where client_cert_fingerprint like 'dummy:%');
delete from audit_gap where node_id in (select id from node where client_cert_fingerprint like 'dummy:%');
delete from node where client_cert_fingerprint like 'dummy:%';
SQL
    psql -c "vacuum (full, analyze) audit_event_default"
    "$0" size
    ;;
  *) sed -n '2,7p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
