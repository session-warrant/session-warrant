package io.seswar.warrant.domain.audit;

import java.time.Instant;
import java.util.UUID;

/**
 * 유실 구간. <b>"빈 구간"을 숨기지 않고 명시적으로 기록한다</b>(§14) —
 * 감추면 조사자가 "이 시간대에는 아무 일도 없었다"로 잘못 읽는다.
 */
// @Entity @Table(name = "audit_gap")
public class EventGap {

    private UUID id;

    private UUID nodeId;

    private Instant from;

    private Instant to;

    /** 커널 ringbuf 가 보고한 드롭 카운트. 알 수 없으면 null. */
    private Long droppedCount;

    /** RINGBUF_OVERFLOW · AGENT_DOWN · CENTRAL_UNREACHABLE 등. */
    private String cause;
}
