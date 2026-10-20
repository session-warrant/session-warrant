-- 재전송 멱등을 감사 이벤트 밖으로도 넓힌다.
-- warrantd 는 재연결하면 마지막 ack 이후를 다시 보낸다. audit_event 는 V1 의 UNIQUE 로 건너뛰지만
-- 무영장 세션 · 유실 구간은 키가 없어서 같은 로그인이 두 번, 같은 빈 구간이 두 번 남았다.

-- 무영장 세션은 그 세션을 실어 온 감사 이벤트의 키를 그대로 쓴다.
-- 아직 행이 없는 테이블이라 기본값 없이 NOT NULL 을 건다.
ALTER TABLE unwarranted_session
    ADD COLUMN seq_epoch BIGINT NOT NULL,
    ADD COLUMN node_seq  BIGINT NOT NULL,
    ADD CONSTRAINT unwarranted_session_idempotency UNIQUE (node_id, seq_epoch, node_seq);

-- GapReport 에는 순번이 없다. warrantd 가 bbolt 에 담아 둔 구간은 재전송에도 같으므로 구간 자체가 키다.
ALTER TABLE audit_gap
    ADD CONSTRAINT audit_gap_idempotency UNIQUE (node_id, from_at, to_at, cause);
