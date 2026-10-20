-- Session Warrant 베이스라인 스키마 (proto 2026-09-23 확정본 기준)
--
-- 원칙 세 가지
--   1) 계보(warrant_lineage)가 원본이고 warrant 의 현재 상태는 파생이다.
--      조회 편의로 비정규화해 두되 방향을 뒤집지 않는다.
--   2) audit_event 는 일 단위 range 파티션 + BRIN. 조회는 항상 시간 범위를 강제해 프루닝이 걸리게 한다.
--   3) subject.kernel_subject_id 는 재사용 금지. 재사용하면 과거 로그의 귀속이 조용히 뒤바뀐다.
--
-- 커널로 내려가는 id 세 개(warrant_id · kernel_subject_id · kernel_policy_id)는 전용 시퀀스로만 뽑는다.
-- 시퀀스는 되감지 않으므로 재사용이 구조적으로 막힌다.
-- proto enum 을 그대로 옮긴 칼럼(mode · on_expiry · effect · proto · verdict · tag_source · origin)은
-- SMALLINT 에 proto 번호를 담는다. 서버에만 있는 상태(state · lineage type · reason · cause)는 TEXT.

-- ------------------------------------------------------------------ 주체

CREATE SEQUENCE kernel_subject_id_seq AS INTEGER MINVALUE 1;

CREATE TABLE subject (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    oidc_subject      TEXT    NOT NULL UNIQUE,
    principal         TEXT    NOT NULL,
    display_name      TEXT,
    kernel_subject_id INTEGER NOT NULL UNIQUE DEFAULT nextval('kernel_subject_id_seq'),
    login_account     TEXT
);

CREATE TABLE subject_ssh_key (
    subject_id    UUID        NOT NULL REFERENCES subject (id),
    fingerprint   TEXT        NOT NULL UNIQUE,  -- 한 키가 두 사람에게 등록되면 바인딩이 다시 모호해진다
    registered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at    TIMESTAMPTZ,
    PRIMARY KEY (subject_id, fingerprint)
);

-- ------------------------------------------------------------------ 정책 (한 행 = 한 버전, 불변)

CREATE SEQUENCE kernel_policy_id_seq AS INTEGER MINVALUE 1;

CREATE TABLE policy (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kernel_policy_id INTEGER     NOT NULL UNIQUE DEFAULT nextval('kernel_policy_id_seq'),  -- rule_* 맵 키
    supersedes_id    UUID REFERENCES policy (id),  -- 수정은 새 행
    name             TEXT        NOT NULL,
    inspect_udp      BOOLEAN     NOT NULL DEFAULT false,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE policy_exec_rule (
    policy_id UUID NOT NULL REFERENCES policy (id),
    path      TEXT NOT NULL,
    PRIMARY KEY (policy_id, path)
);

CREATE TABLE policy_write_rule (
    policy_id UUID     NOT NULL REFERENCES policy (id),
    path      TEXT     NOT NULL,
    recursive BOOLEAN  NOT NULL,
    effect    SMALLINT NOT NULL CHECK (effect IN (1, 2)),  -- 1 ALLOW · 2 DENY. 0(UNSPECIFIED)은 저장 불가
    PRIMARY KEY (policy_id, path)
    -- effect=DENY 는 디렉터리만 — 경로만으로는 알 수 없어 PolicyLinter 가 막는다
);

CREATE TABLE policy_net_rule (
    policy_id UUID     NOT NULL REFERENCES policy (id),
    cidr      CIDR     NOT NULL,
    port      INTEGER  NOT NULL CHECK (port BETWEEN 0 AND 65535),  -- 0 = 전체
    proto     SMALLINT NOT NULL CHECK (proto IN (0, 1, 2)),       -- ANY · TCP · UDP
    PRIMARY KEY (policy_id, cidr, port, proto)
);

CREATE TABLE policy_read_watch (
    policy_id UUID NOT NULL REFERENCES policy (id),
    path      TEXT NOT NULL,
    PRIMARY KEY (policy_id, path)
);

-- ------------------------------------------------------------------ 노드

CREATE TABLE node (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_cert_fingerprint TEXT    NOT NULL UNIQUE,  -- 노드 신원은 mTLS 인증서
    hostname                TEXT    NOT NULL,         -- 자기 신고라 UNIQUE 키로 쓰지 않는다
    kernel_version          TEXT,
    bpf_lsm_enabled         BOOLEAN NOT NULL DEFAULT false,
    agent_version           TEXT,
    attached_hooks          TEXT[]  NOT NULL DEFAULT '{}',
    current_seq_epoch       BIGINT,
    last_seen_at            TIMESTAMPTZ,
    booted_at               TIMESTAMPTZ
);

-- ------------------------------------------------------------------ 영장

CREATE SEQUENCE warrant_kernel_id_seq AS BIGINT MINVALUE 1;  -- 0 은 "무영장" 자리

CREATE TABLE warrant (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    warrant_id     BIGINT      NOT NULL UNIQUE DEFAULT nextval('warrant_kernel_id_seq') CHECK (warrant_id > 0),
    revision       INTEGER     NOT NULL CHECK (revision >= 1),
    display_id     TEXT        NOT NULL UNIQUE,
    subject_id     UUID        NOT NULL REFERENCES subject (id),
    login_account  TEXT        NOT NULL,
    policy_id      UUID        NOT NULL REFERENCES policy (id),
    reason         TEXT        NOT NULL,
    issued_at      TIMESTAMPTZ,
    expires_at     TIMESTAMPTZ NOT NULL,  -- 절대 시각. boot 기준 변환은 warrantd 가 한다
    grace_window   INTERVAL    NOT NULL DEFAULT '0',  -- grace_until 은 저장하지 않는다 — expires_at + grace_window
    mode           SMALLINT    NOT NULL CHECK (mode IN (0, 1, 2)),       -- OBSERVE · DRYRUN · ENFORCE
    on_expiry      SMALLINT    NOT NULL CHECK (on_expiry IN (0, 1, 2)),  -- DEMOTE · KILL · SESSION_ONLY_GRACE
    state          TEXT        NOT NULL,
    revoked        BOOLEAN     NOT NULL DEFAULT false,
    break_glass    BOOLEAN     NOT NULL DEFAULT false,
    signed_payload BYTEA,  -- 발급 전(REQUESTED)에는 비어 있다
    signature      BYTEA,
    signing_key_id TEXT
);

CREATE INDEX warrant_subject_idx ON warrant (subject_id);

CREATE TABLE warrant_ssh_key (  -- 발급 시점 스냅샷. 서명된 봉투와 같아야 한다
    warrant_id  UUID NOT NULL REFERENCES warrant (id),
    fingerprint TEXT NOT NULL,
    PRIMARY KEY (warrant_id, fingerprint)
);

CREATE TABLE warrant_target_host (
    warrant_id UUID NOT NULL REFERENCES warrant (id),
    hostname   TEXT NOT NULL,
    PRIMARY KEY (warrant_id, hostname)
    -- 활성 1개 불변식 (subject, hostname, login_account): 발급 서비스가 subject 행을
    -- FOR UPDATE 로 직렬화해 지킨다. 대상 호스트가 자식 테이블이라 부분 UNIQUE 로는 못 건다
);

CREATE TABLE warrant_lineage (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    warrant_id       UUID        NOT NULL REFERENCES warrant (id),
    type             TEXT        NOT NULL,
    occurred_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_id         UUID REFERENCES subject (id),  -- warrantd 자동 요청 · 정책 자동 승인은 비어 있다
    reason           TEXT,
    basis            TEXT,
    delta_seconds    BIGINT,
    expires_at_after TIMESTAMPTZ
);

CREATE INDEX warrant_lineage_warrant_idx ON warrant_lineage (warrant_id, occurred_at);

-- append-only. 계보를 고치면 원본이 사라진다
CREATE FUNCTION warrant_lineage_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'warrant_lineage is append-only (% rejected)', TG_OP;
END;
$$;

CREATE TRIGGER warrant_lineage_no_update_delete
    BEFORE UPDATE OR DELETE ON warrant_lineage
    FOR EACH ROW EXECUTE FUNCTION warrant_lineage_append_only();

-- TRUNCATE 는 행 트리거를 거치지 않으므로 따로 막는다
CREATE TRIGGER warrant_lineage_no_truncate
    BEFORE TRUNCATE ON warrant_lineage
    FOR EACH STATEMENT EXECUTE FUNCTION warrant_lineage_append_only();

-- ------------------------------------------------------------------ 감사

CREATE TABLE audit_event (
    id                UUID        NOT NULL DEFAULT gen_random_uuid(),
    occurred_at       TIMESTAMPTZ NOT NULL,  -- warrantd 가 bbolt 에 담아 둔 값. 재전송에도 같다
    node_id           UUID        NOT NULL REFERENCES node (id),
    seq_epoch         BIGINT      NOT NULL,
    node_seq          BIGINT      NOT NULL,
    warrant_id        BIGINT      NOT NULL DEFAULT 0,  -- 커널 u64 (warrant.warrant_id 와 조인). 0 = 무영장
    kernel_subject_id INTEGER,
    type              TEXT        NOT NULL,
    verdict           SMALLINT    NOT NULL,
    mode              SMALLINT,
    tag_source        SMALLINT    NOT NULL,
    origin            SMALLINT    NOT NULL,
    pid               BIGINT,
    cgroup_id         BIGINT,
    uid               INTEGER,
    device_id         BIGINT,  -- 신뢰의 근거는 (device_id, inode) 다
    inode             BIGINT,
    resolved_path     TEXT,    -- 참고 정보
    argv_truncated    TEXT,    -- 참고 정보. exec -a 로 위조 가능
    destination       TEXT,
    PRIMARY KEY (id, occurred_at),
    UNIQUE (node_id, seq_epoch, node_seq, occurred_at)  -- 재전송 멱등. 파티션 키를 포함해야 한다
) PARTITION BY RANGE (occurred_at);

-- 일 단위 파티션 생성은 아직 없다. 그 전까지는 전부 기본 파티션에 들어간다
CREATE TABLE audit_event_default PARTITION OF audit_event DEFAULT;

CREATE INDEX audit_event_occurred_brin ON audit_event USING brin (occurred_at);
CREATE INDEX audit_event_warrant_idx ON audit_event (warrant_id, occurred_at);

CREATE TABLE audit_gap (  -- 빈 구간을 숨기지 않는다
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id       UUID        NOT NULL REFERENCES node (id),
    from_at       TIMESTAMPTZ NOT NULL,
    to_at         TIMESTAMPTZ NOT NULL,
    dropped_count BIGINT,  -- 모르면 NULL. 0 과 구분한다
    cause         TEXT        NOT NULL
);

CREATE INDEX audit_gap_node_idx ON audit_gap (node_id, from_at);

CREATE TABLE unwarranted_session (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id              UUID        NOT NULL REFERENCES node (id),
    observed_at          TIMESTAMPTZ NOT NULL,
    login_account        TEXT,
    ssh_key_fingerprint  TEXT,  -- 비어 있으면 NO_KEY. 이 값으로 사람을 역추적한다
    source_address       TEXT,
    cgroup_id            BIGINT      NOT NULL,
    reason               TEXT        NOT NULL,
    observed_event_count BIGINT      NOT NULL DEFAULT 0
);

CREATE INDEX unwarranted_session_observed_idx ON unwarranted_session (observed_at);
