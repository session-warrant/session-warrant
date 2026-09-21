package io.seswar.warrant.repository;

/**
 * 일 단위 range 파티션 + BRIN 인덱스. 데모 규모에서는 PostgreSQL 하나로 충분하다(기술 스택 §07).
 *
 * <p>적재는 JPA 가 아니라 <b>배치 INSERT</b>로 한다.
 * 엔티티 단건 저장으로는 ringbuf 유입량을 못 따라간다.
 */
// @Repository
public interface AuditEventRepository {

    // insertBatch(List<AuditEvent>)            — ON CONFLICT (node_id, node_seq) DO NOTHING
    // search(AuditQuery)                        — 파티션 프루닝이 걸리게 항상 시간 범위를 강제한다
    // countByWarrantId(UUID)
}
