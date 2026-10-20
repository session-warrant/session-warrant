package io.seswar.warrant.domain.audit;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

/**
 * 유실 구간. <b>"빈 구간"을 숨기지 않고 명시적으로 기록한다</b>(§14) —
 * 감추면 조사자가 "이 시간대에는 아무 일도 없었다"로 잘못 읽는다.
 */
@Entity
@Table(name = "audit_gap")
public class EventGap {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false)
    private UUID nodeId;

    @Column(name = "from_at", nullable = false)  // from · to 는 SQL 예약어
    private Instant from;

    @Column(name = "to_at", nullable = false)
    private Instant to;

    /** 커널 ringbuf 가 보고한 드롭 카운트. 알 수 없으면 null. */
    private Long droppedCount;

    /** proto {@code GapReport.Cause}: RINGBUF_OVERFLOW · AGENT_DOWN · LOCAL_STORE_FULL · CPU_SEQ_SKIP. */
    @Column(nullable = false)
    private String cause;

    protected EventGap() {
    }

    // Called by the gRPC layer for each GapReport in a batch. droppedCount is null when unknown.
    public static EventGap of(UUID nodeId, Instant from, Instant to, Long droppedCount, String cause) {
        EventGap g = new EventGap();
        g.nodeId = nodeId;
        g.from = from;
        g.to = to;
        g.droppedCount = droppedCount;
        g.cause = cause;
        return g;
    }

    public UUID getId() { return id; }

    public UUID getNodeId() { return nodeId; }

    public Instant getFrom() { return from; }

    public Instant getTo() { return to; }

    public Long getDroppedCount() { return droppedCount; }

    public String getCause() { return cause; }
}
