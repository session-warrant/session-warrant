-- 허용된 쓰기의 집계(§14). 차단은 audit_event 에 전건이 남고, 허용 쓰기는 영장 · 막대별 건수만 남긴다.
--
-- 노드는 막대 하나의 누적 건수를 보낸다(증분이 아니다). 재전송되면 같은 행이 다시 오고, 막대가 닫히기 전에
-- 여러 번 오면 건수가 커진다 — 그래서 키가 같으면 큰 값을 남긴다. 합산하면 재전송이 건수를 부풀린다.
CREATE TABLE write_aggregate (
    node_id       UUID        NOT NULL REFERENCES node (id),
    warrant_id    BIGINT      NOT NULL,  -- 커널 u64. warrant.warrant_id 와 조인
    bucket_start  TIMESTAMPTZ NOT NULL,
    bucket_ns     BIGINT      NOT NULL CHECK (bucket_ns > 0),
    allowed_count BIGINT      NOT NULL CHECK (allowed_count >= 0),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (node_id, warrant_id, bucket_start, bucket_ns)
);

CREATE INDEX write_aggregate_bucket_idx ON write_aggregate (bucket_start);
CREATE INDEX write_aggregate_warrant_idx ON write_aggregate (warrant_id, bucket_start);
