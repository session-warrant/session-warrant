package io.seswar.warrant.audit;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

public interface WarrantedSessionRepository extends JpaRepository<WarrantedSession, UUID> {

    // Called by AuditIngestService before saving. Keys among [minSeq, maxSeq] already stored for this node.
    @Query("""
            select new io.seswar.warrant.audit.SeqKey(s.seqEpoch, s.nodeSeq)
            from WarrantedSession s
            where s.nodeId = :nodeId and s.seqEpoch in :epochs and s.nodeSeq between :minSeq and :maxSeq
            """)
    List<SeqKey> findExistingKeys(@Param("nodeId") UUID nodeId, @Param("epochs") Collection<Long> epochs,
                                  @Param("minSeq") long minSeq, @Param("maxSeq") long maxSeq);
}
