-- 영장이 맞아 cgroup 에 태그된 SSH 세션. 무영장 세션(unwarranted_session)과 짝이다.
-- 키는 그 세션을 실어 온 감사 이벤트의 키를 그대로 쓴다(V2 와 같은 규칙).
CREATE TABLE warranted_session (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id             UUID        NOT NULL REFERENCES node (id),
    seq_epoch           BIGINT      NOT NULL,
    node_seq            BIGINT      NOT NULL,
    observed_at         TIMESTAMPTZ NOT NULL,
    warrant_id          BIGINT      NOT NULL,  -- 커널 u64. warrant.warrant_id 와 조인
    kernel_subject_id   INTEGER,
    mode                TEXT        NOT NULL,  -- OBSERVE · DRYRUN · ENFORCE
    login_account       TEXT,
    ssh_key_fingerprint TEXT,
    source_address      TEXT,
    cgroup_id           BIGINT      NOT NULL,
    CONSTRAINT warranted_session_idempotency UNIQUE (node_id, seq_epoch, node_seq)
);

CREATE INDEX warranted_session_observed_idx ON warranted_session (observed_at);

-- 조직 전체 SSH 접속 현황 — 영장 세션과 무영장 세션을 한 줄씩. Grafana 가 이 뷰를 읽는다.
CREATE VIEW ssh_session AS
SELECT observed_at, node_id, true AS warranted, warrant_id, mode, NULL::text AS reason,
       login_account, ssh_key_fingerprint, source_address, cgroup_id
FROM warranted_session
UNION ALL
SELECT observed_at, node_id, false, 0, NULL, reason,
       login_account, ssh_key_fingerprint, source_address, cgroup_id
FROM unwarranted_session;
