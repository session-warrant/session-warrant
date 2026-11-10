package io.seswar.warrant.warrant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

/**
 * 계보 한 줄. <b>append-only</b> 이며 수정 · 삭제하지 않는다.
 *
 * <p>이벤트 소싱까지 갈 필요는 없다 — append-only 테이블이면 충분하고,
 * 현재 상태는 뷰로 계산한다(기술 스택 §07).
 */
@Entity
@Table(name = "warrant_lineage")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class WarrantLineage {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /** warrant.id (서버 PK) — 커널 warrant_id 가 아니다. */
    @Column(nullable = false)
    private UUID warrantId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private LineageType type;

    @Column(nullable = false)
    private Instant occurredAt;

    /** 한 사람(subject). 자동 승인이면 null 이고 {@link #basis} 에 근거가 들어간다. */
    private UUID actorId;

    /** 사람이 적은 사유. 예: "배포 지연". */
    private String reason;

    /** 자동 승인의 근거. 예: "read-only 정책 2회차". */
    private String basis;

    /** 이 이벤트로 바뀐 유효기간. 신청이면 신청한 기간, 연장이면 +30m. */
    private Long deltaSeconds;

    /** 이벤트 직후의 만료 시각. 스냅샷으로 남겨 두면 감사 조회에서 재계산이 필요 없다. */
    private Instant expiresAtAfter;

    public static WarrantLineage of(UUID warrantId, LineageType type, Instant at, UUID actorId, String reason,
                                    Duration delta, Instant expiresAtAfter) {
        WarrantLineage l = new WarrantLineage();
        l.warrantId = warrantId;
        l.type = type;
        l.occurredAt = at;
        l.actorId = actorId;
        l.reason = reason;
        l.deltaSeconds = delta == null ? null : delta.toSeconds();
        l.expiresAtAfter = expiresAtAfter;
        return l;
    }

    public Duration delta() {
        return deltaSeconds == null ? null : Duration.ofSeconds(deltaSeconds);
    }
}
