package io.seswar.warrant.repository;

import io.seswar.warrant.domain.audit.UnwarrantedSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

/** 아래 두 쿼리의 결과가 §07 STEP 2 의 리포트 한 장이 된다. 기간은 [from, to). */
public interface UnwarrantedSessionRepository extends JpaRepository<UnwarrantedSession, UUID> {

    interface NodeSummary {
        UUID getNodeId();
        long getSessions();
        long getEvents();
    }

    interface AccountSummary {
        String getLoginAccount();
        long getSessions();
        long getEvents();
    }

    // Called by AuditIngestService before saving. Keys among [minSeq, maxSeq] already stored for this node.
    @Query("""
            select new io.seswar.warrant.repository.SeqKey(u.seqEpoch, u.nodeSeq)
            from UnwarrantedSession u
            where u.nodeId = :nodeId and u.seqEpoch in :epochs and u.nodeSeq between :minSeq and :maxSeq
            """)
    List<SeqKey> findExistingKeys(@Param("nodeId") UUID nodeId, @Param("epochs") Collection<Long> epochs,
                                  @Param("minSeq") long minSeq, @Param("maxSeq") long maxSeq);

    // Called by UnwarrantedSessionDetector.summarize. Sessions and their event counts per node.
    @Query("""
            select u.nodeId as nodeId, count(u) as sessions, coalesce(sum(u.observedEventCount), 0) as events
            from UnwarrantedSession u
            where u.observedAt >= :from and u.observedAt < :to
            group by u.nodeId
            order by count(u) desc
            """)
    List<NodeSummary> summarizeByNode(@Param("from") Instant from, @Param("to") Instant to);

    // Called by UnwarrantedSessionDetector.summarize. Sessions and their event counts per login account.
    @Query("""
            select u.loginAccount as loginAccount, count(u) as sessions, coalesce(sum(u.observedEventCount), 0) as events
            from UnwarrantedSession u
            where u.observedAt >= :from and u.observedAt < :to
            group by u.loginAccount
            order by count(u) desc
            """)
    List<AccountSummary> summarizeByAccount(@Param("from") Instant from, @Param("to") Instant to);
}
