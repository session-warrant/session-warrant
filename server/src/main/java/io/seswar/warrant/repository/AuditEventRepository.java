package io.seswar.warrant.repository;

import io.seswar.warrant.domain.audit.AuditEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

/**
 * 일 단위 range 파티션 + BRIN 인덱스. 데모 규모에서는 PostgreSQL 하나로 충분하다(기술 스택 §07).
 *
 * <p>적재는 saveAll + Hibernate JDBC 배치(application.yml {@code hibernate.jdbc.batch_size}).
 * 조회는 파티션 프루닝이 걸리게 항상 시간 범위를 받는다.
 */
public interface AuditEventRepository extends JpaRepository<AuditEvent, UUID> {

    // Called by AuditIngestService before saving a batch. Keys among [minSeq, maxSeq] already stored for this node.
    @Query("""
            select new io.seswar.warrant.repository.SeqKey(e.seqEpoch, e.nodeSeq)
            from AuditEvent e
            where e.nodeId = :nodeId and e.seqEpoch in :epochs and e.nodeSeq between :minSeq and :maxSeq
            """)
    List<SeqKey> findExistingKeys(@Param("nodeId") UUID nodeId, @Param("epochs") Collection<Long> epochs,
                                  @Param("minSeq") long minSeq, @Param("maxSeq") long maxSeq);

    // Events attributed to one kernel warrant id within [from, to).
    long countByWarrantIdAndOccurredAtGreaterThanEqualAndOccurredAtLessThan(long warrantId, Instant from, Instant to);

    // 남은 것: search(AuditQuery) — 감사 조회 API 를 붙일 때.
}
