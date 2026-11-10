-- 서버가 받은 순서. 대시보드는 이 값으로 "마지막으로 받은 뒤"를 이어 받는다.
-- occurred_at 으로 이어 받으면 재전송된 과거 기록(서버가 죽어 있던 동안 노드가 쌓아 둔 것)이 영영 빠진다.
-- 순번 순서 = 커밋 순서가 되도록 AuditIngestService 가 적재를 직렬화한다(advisory lock).
CREATE SEQUENCE audit_event_received_seq;

ALTER TABLE audit_event
    ADD COLUMN received_seq BIGINT NOT NULL DEFAULT nextval('audit_event_received_seq');

ALTER SEQUENCE audit_event_received_seq OWNED BY audit_event.received_seq;

-- 파티션 키가 없어 UNIQUE 는 못 건다. 시퀀스가 유일성을 준다.
CREATE INDEX audit_event_received_idx ON audit_event (received_seq);
