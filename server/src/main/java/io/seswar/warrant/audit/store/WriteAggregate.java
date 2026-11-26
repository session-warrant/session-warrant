package io.seswar.warrant.audit.store;

import java.time.Instant;
import java.util.UUID;

/**
 * 허용된 쓰기의 집계 한 칸(V6 {@code write_aggregate}). 영장 하나 · 막대 하나의 <b>누적</b> 건수다.
 * JPA 엔티티가 아니다 — 같은 키가 다시 오면 큰 값을 남기는 upsert 라서 {@code AuditIngestService} 가 JDBC 로 쓴다.
 */
public record WriteAggregate(UUID nodeId, long warrantId, Instant bucketStart, long bucketNs, long allowedCount) {

    /** 테이블의 기본 키. 한 배치 안에서 같은 키가 두 번 오면 하나로 합친다. */
    public record Key(UUID nodeId, long warrantId, Instant bucketStart, long bucketNs) {
    }

    public Key key() {
        return new Key(nodeId, warrantId, bucketStart, bucketNs);
    }
}
