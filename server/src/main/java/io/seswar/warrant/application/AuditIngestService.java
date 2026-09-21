package io.seswar.warrant.application;

import io.seswar.warrant.domain.audit.AuditEvent;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * 감사 이벤트 수집. 메시지 큐는 넣지 않는다 — gRPC 스트리밍에 백프레셔가 이미 있고,
 * 중앙이 잠깐 죽어도 warrantd 의 로컬 버퍼가 받아 준다(기술 스택 §07).
 */
// @Service
public class AuditIngestService {

    /**
     * 중복 수신을 전제로 설계한다 — warrantd 가 재연결하면 마지막 ack 이후를 다시 보낸다.
     * (node_id, node_seq) 유니크로 멱등하게 받는 편이 재전송 로직보다 단순하다.
     */
    public void ingest(UUID nodeId, List<AuditEvent> batch) {
        // 1. 멱등 적재 (ON CONFLICT DO NOTHING)
        // 2. kernelSubjectId → Subject 조인은 여기서 하지 않는다. 조회 시점에 한다 —
        //    수집 경로에 조인을 넣으면 처리량이 주체 테이블 락에 묶인다
        // 3. SELF_PROTECTION_HIT 이나 UNWARRANTED_SESSION 이 섞여 있으면 즉시 경보로 분기
        throw new UnsupportedOperationException("미구현");
    }

    /** warrantd 가 보고한 유실 구간을 그대로 남긴다 ({@link io.seswar.warrant.domain.audit.EventGap}). */
    public void recordGap(UUID nodeId, Instant from, Instant to, Long droppedCount, String cause) {
        throw new UnsupportedOperationException("미구현");
    }

    /**
     * 허용된 쓰기는 전건이 아니라 집계로 받는다(§14).
     * 차단은 언제나 전건 기록이지만, 허용 쓰기까지 다 남기면 ringbuf 가 넘친다.
     */
    public void ingestWriteAggregate(UUID nodeId, UUID warrantId, Instant bucket, long count) {
        throw new UnsupportedOperationException("미구현");
    }
}
