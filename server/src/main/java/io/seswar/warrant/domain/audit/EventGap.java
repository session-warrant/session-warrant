package io.seswar.warrant.domain.audit;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

/** 유실 구간 — 빈 구간을 숨기지 않는다(§14). 필드의 뜻과 제약은 server/README.md 「감사 엔티티」. */
@Entity
@Table(name = "audit_gap")
public class EventGap {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false)
    private UUID nodeId;

    @Column(name = "from_at", nullable = false)
    private Instant from;

    @Column(name = "to_at", nullable = false)
    private Instant to;

    private Long droppedCount;

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
