package io.seswar.warrant.audit;

import io.seswar.warrant.audit.AuditEvent;
import io.seswar.warrant.audit.EventGap;
import io.seswar.warrant.audit.UnwarrantedSession;
import io.seswar.warrant.audit.AuditEventRepository;
import io.seswar.warrant.audit.EventGapRepository;
import io.seswar.warrant.audit.SeqKey;
import io.seswar.warrant.audit.UnwarrantedSessionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationEventPublisher;
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
 * AuditEvent를 DB에 작성
 */
@Service
@RequiredArgsConstructor
public class AuditIngestService {


    private final AuditEventRepository events;
    private final EventGapRepository gaps;
    private final UnwarrantedSessionRepository unwarranted;
    private final WarrantedSessionRepository warranted;
    private final ApplicationEventPublisher publisher;

    // pg_advisory_xact_lock key for audit ingest. Any constant works; this one is "swaudit\0" in ASCII.
    static final long INGEST_LOCK = 0x7377617564697400L;


    public record Batch(List<AuditEvent> events, List<EventGap> gaps, List<UnwarrantedSession> unwarrantedSessions,
                        List<WarrantedSession> warrantedSessions) {
        public Batch {
            events = List.copyOf(events);
            gaps = List.copyOf(gaps);
            unwarrantedSessions = List.copyOf(unwarrantedSessions);
            warrantedSessions = List.copyOf(warrantedSessions);
        }

        public Batch(List<AuditEvent> events, List<EventGap> gaps, List<UnwarrantedSession> unwarrantedSessions) {
            this(events, gaps, unwarrantedSessions, List.of());
        }
    }

    /** 이번 배치에서 새로 들어간 행 수. 재전송이면 전부 0 이다. 새 행이 있으면 커밋 뒤 AuditStream 이 화면에 알린다. */
    public record Result(int events, int gaps, int unwarrantedSessions, int warrantedSessions) {
        public Result(int events, int gaps, int unwarrantedSessions) {
            this(events, gaps, unwarrantedSessions, 0);
        }

        boolean empty() {
            return events == 0 && gaps == 0 && unwarrantedSessions == 0 && warrantedSessions == 0;
        }
    }


    /**
     * 배치 하나 저장. 노드가 여럿이어도 한 번에 하나씩 — 수신 순번(received_seq) 순서가 커밋 순서와 같아야
     * 대시보드가 "순번 N 이후"로 이어 받을 때 늦게 커밋된 작은 순번을 건너뛰지 않는다.
     */
    @Transactional
    public Result ingest(UUID nodeId, Batch batch) {
        requireNode(nodeId, batch);
        events.lockIngest(INGEST_LOCK);

        List<AuditEvent> newEvents = onlyNew(batch.events(), AuditEvent::getSeqEpoch, AuditEvent::getNodeSeq,
                (epochs, min, max) -> events.findExistingKeys(nodeId, epochs, min, max));
        List<UnwarrantedSession> newSessions = onlyNew(batch.unwarrantedSessions(),
                UnwarrantedSession::getSeqEpoch, UnwarrantedSession::getNodeSeq,
                (epochs, min, max) -> unwarranted.findExistingKeys(nodeId, epochs, min, max));
        List<WarrantedSession> newWarranted = onlyNew(batch.warrantedSessions(),
                WarrantedSession::getSeqEpoch, WarrantedSession::getNodeSeq,
                (epochs, min, max) -> warranted.findExistingKeys(nodeId, epochs, min, max));
        Set<List<Object>> gapKeys = new HashSet<>();
        List<EventGap> newGaps = batch.gaps().stream()
                .filter(g -> gapKeys.add(List.of(g.getFrom(), g.getTo(), g.getCause())))
                .filter(g -> !gaps.existsByNodeIdAndFromAndToAndCause(nodeId, g.getFrom(), g.getTo(), g.getCause()))
                .toList();

        events.saveAllAndFlush(newEvents);
        gaps.saveAllAndFlush(newGaps);
        unwarranted.saveAllAndFlush(newSessions);
        warranted.saveAllAndFlush(newWarranted);
        Result result = new Result(newEvents.size(), newGaps.size(), newSessions.size(), newWarranted.size());
        if (!result.empty()) {
            publisher.publishEvent(result);
        }
        return result;
    }

    /** warrantd 가 보고한 유실 구간을 그대로 남긴다 ({@link EventGap}). */
    @Transactional
    public void recordGap(UUID nodeId, Instant from, Instant to, Long droppedCount, String cause) {
        if (!gaps.existsByNodeIdAndFromAndToAndCause(nodeId, from, to, cause)) {
            gaps.saveAndFlush(EventGap.of(nodeId, from, to, droppedCount, cause));
            publisher.publishEvent(new Result(0, 1, 0));
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
                && batch.unwarrantedSessions().stream().allMatch(x -> nodeId.equals(x.getNodeId()))
                && batch.warrantedSessions().stream().allMatch(x -> nodeId.equals(x.getNodeId()));
        if (!ok) {
            throw new IllegalArgumentException("batch contains rows for a node other than " + nodeId);
        }
    }
}
