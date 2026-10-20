package io.seswar.warrant.application;

import io.seswar.warrant.domain.audit.AuditEvent;
import io.seswar.warrant.domain.audit.EventGap;
import io.seswar.warrant.domain.audit.UnwarrantedSession;
import io.seswar.warrant.repository.AuditEventRepository;
import io.seswar.warrant.repository.EventGapRepository;
import io.seswar.warrant.repository.SeqKey;
import io.seswar.warrant.repository.UnwarrantedSessionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.function.ToLongFunction;
import java.util.stream.Collectors;

/**
 * 감사 이벤트 수집. 메시지 큐는 넣지 않는다 — gRPC 스트리밍에 백프레셔가 이미 있고,
 * 중앙이 잠깐 죽어도 warrantd 의 로컬 버퍼가 받아 준다(기술 스택 §07).
 */
@Service
@RequiredArgsConstructor
public class AuditIngestService {


    private final AuditEventRepository events;
    private final EventGapRepository gaps;
    private final UnwarrantedSessionRepository unwarranted;


    public record Batch(List<AuditEvent> events, List<EventGap> gaps, List<UnwarrantedSession> unwarrantedSessions) {
        public Batch {
            events = List.copyOf(events);
            gaps = List.copyOf(gaps);
            unwarrantedSessions = List.copyOf(unwarrantedSessions);
        }
    }

    /** 이번 배치에서 새로 들어간 행 수. 재전송이면 전부 0 이다. */
    public record Result(int events, int gaps, int unwarrantedSessions) {
    }


    // Called by AuditIngestGrpcService for each AuditBatch, before it acks.
    // Stores events, gaps and unwarranted sessions in one transaction, skipping rows already stored (server/README.md).
    @Transactional
    public Result ingest(UUID nodeId, Batch batch) {
        requireNode(nodeId, batch);

        List<AuditEvent> newEvents = onlyNew(batch.events(), AuditEvent::getSeqEpoch, AuditEvent::getNodeSeq,
                (epochs, min, max) -> events.findExistingKeys(nodeId, epochs, min, max));
        List<UnwarrantedSession> newSessions = onlyNew(batch.unwarrantedSessions(),
                UnwarrantedSession::getSeqEpoch, UnwarrantedSession::getNodeSeq,
                (epochs, min, max) -> unwarranted.findExistingKeys(nodeId, epochs, min, max));
        Set<List<Object>> gapKeys = new HashSet<>();
        List<EventGap> newGaps = batch.gaps().stream()
                .filter(g -> gapKeys.add(List.of(g.getFrom(), g.getTo(), g.getCause())))
                .filter(g -> !gaps.existsByNodeIdAndFromAndToAndCause(nodeId, g.getFrom(), g.getTo(), g.getCause()))
                .toList();

        events.saveAllAndFlush(newEvents);
        gaps.saveAllAndFlush(newGaps);
        unwarranted.saveAllAndFlush(newSessions);
        return new Result(newEvents.size(), newGaps.size(), newSessions.size());
    }

    /** warrantd 가 보고한 유실 구간을 그대로 남긴다 ({@link EventGap}). */
    @Transactional
    public void recordGap(UUID nodeId, Instant from, Instant to, Long droppedCount, String cause) {
        if (!gaps.existsByNodeIdAndFromAndToAndCause(nodeId, from, to, cause)) {
            gaps.saveAndFlush(EventGap.of(nodeId, from, to, droppedCount, cause));
        }
    }

    /**
     * 허용된 쓰기는 전건이 아니라 집계로 받는다(§14).
     * 차단은 언제나 전건 기록이지만, 허용 쓰기까지 다 남기면 ringbuf 가 넘친다.
     */
    public void ingestWriteAggregate(UUID nodeId, UUID warrantId, Instant bucket, long count) {

        throw new UnsupportedOperationException("미구현");
    }

    private interface KeyLookup {
        List<SeqKey> existing(Set<Long> epochs, long minSeq, long maxSeq);
    }

    // Drops rows whose (seqEpoch, nodeSeq) is already stored, or repeated inside the same batch.
    private static <T> List<T> onlyNew(List<T> rows, ToLongFunction<T> epoch, ToLongFunction<T> seq, KeyLookup lookup) {
        if (rows.isEmpty()) {
            return List.of();
        }
        Set<Long> epochs = rows.stream().map(r -> epoch.applyAsLong(r)).collect(Collectors.toSet());
        long min = rows.stream().mapToLong(seq).min().orElseThrow();
        long max = rows.stream().mapToLong(seq).max().orElseThrow();
        Set<SeqKey> seen = new HashSet<>(lookup.existing(epochs, min, max));
        List<T> fresh = new ArrayList<>();
        for (T r : rows) {
            if (seen.add(new SeqKey(epoch.applyAsLong(r), seq.applyAsLong(r)))) {
                fresh.add(r);
            }
        }
        return fresh;
    }

    // 한 배치 안의 행이 전부 그 스트림의 노드 것인지. 섞이면 남의 노드 이름으로 기록된다.
    private static void requireNode(UUID nodeId, Batch batch) {
        boolean ok = batch.events().stream().allMatch(x -> nodeId.equals(x.getNodeId()))
                && batch.gaps().stream().allMatch(x -> nodeId.equals(x.getNodeId()))
                && batch.unwarrantedSessions().stream().allMatch(x -> nodeId.equals(x.getNodeId()));
        if (!ok) {
            throw new IllegalArgumentException("batch contains rows for a node other than " + nodeId);
        }
    }
}
