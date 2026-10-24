package io.seswar.warrant.repository;

import io.seswar.warrant.domain.audit.EventGap;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public interface EventGapRepository extends JpaRepository<EventGap, UUID> {

    // Called by AuditIngestService before saving a gap. The interval itself is the replay key (V2).
    boolean existsByNodeIdAndFromAndToAndCause(UUID nodeId, Instant from, Instant to, String cause);

    // Gaps overlapping [from, to) on one node. 조사자가 "이 구간은 비어 있다"를 같이 보게 한다.
    List<EventGap> findByNodeIdAndFromLessThanAndToGreaterThanOrderByFromAsc(UUID nodeId, Instant to, Instant from);
}
