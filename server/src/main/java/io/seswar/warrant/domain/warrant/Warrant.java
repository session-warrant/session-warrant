package io.seswar.warrant.domain.warrant;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * 영장(§02). 필드 구성은 {@code proto/warrant.proto} 와 {@code struct warrant}(§12)에서 그대로 온다 —
 * <b>필드를 여기서만 추가하지 말 것</b>. 항상 .proto 를 먼저 고친다.
 *
 * <pre>
 * struct warrant {
 *     __u64 expires_ns;   // bpf_ktime_get_boot_ns 기준
 *     __u64 grace_ns;     // on_expiry=2 일 때 유예 시한
 *     __u32 subject_id;
 *     __u32 policy_id;
 *     __u8  revoked;
 *     __u8  mode;
 *     __u8  on_expiry;
 * };
 * </pre>
 */
// @Entity @Table(name = "warrant")
public class Warrant {

    private UUID id;

    /** 사람이 읽는 식별자. 예: {@code W-4821-3F}. Slack · 감사 리포트에 나온다. */
    private String displayId;

    /** 주체. {@code subject_id} 로 커널에 내려간다. */
    private UUID subjectId;

    /** 정책. {@code policy_id} 는 rule_exec · rule_write · rule_net 조회 키의 앞부분이 된다. */
    private UUID policyId;

    /** 사유. 예: {@code INC-4821 결제 지연 장애 대응}. 감사에서 "왜"에 답하는 유일한 필드다. */
    private String reason;

    /** 대상 호스트. 예: {@code prod-payment-{03,04}}. 이 목록의 노드에만 push 된다. */
    private List<String> targetHosts;

    private Instant issuedAt;

    /**
     * 만료 시각 — <b>절대 시각으로 보관한다</b>. 커널의 boot 기준 {@code expires_ns} 로의 변환은
     * warrantd 가 한다. 여기서 ns 로 변환하려 들지 말 것 — 시계 스큐가 그대로 만료 오차가 된다.
     */
    private Instant expiresAt;

    /** 유예 시한. on_expiry = SESSION_ONLY_GRACE 일 때만 의미가 있다. 무기한은 허용되지 않는다. */
    private Instant graceUntil;

    private WarrantMode mode;

    private OnExpiry onExpiry;

    private WarrantState state;

    /** 취소 플래그. 커널에서는 1바이트이고, 뒤집는 순간 전 노드에서 즉시 발효된다. */
    private boolean revoked;

    /** 서명된 protobuf 바이트. <b>JSON 이 아니라 이 바이트에 서명한다</b>(정규화 문제 회피). */
    private byte[] signedPayload;

    private byte[] signature;

    /** 발급 → 연장 → 만료의 append-only 계보. "30분짜리 작업이 왜 90분이었나"가 이걸로 설명된다. */
    private List<WarrantLineage> lineage;

    // ---------------------------------------------------------------- 도메인 규칙

    /**
     * 지금 이 시각 기준으로 만료했는가.
     *
     * <p>주의: 이 판정은 <b>서버 측 뷰일 뿐</b>이다. 실제 집행 판정은 커널이 독립적으로 한다.
     * 서버가 만료를 "선언"해서 노드에 알릴 필요는 없다 — 알림이 끊겨도 만료는 정확히 발효된다.
     */
    public boolean isExpiredAt(Instant now) {
        // return now.isAfter(expiresAt);
        throw new UnsupportedOperationException("미구현");
    }

    /** 유예 구간에 있는가 (만료했지만 grace 안). */
    public boolean isInGraceAt(Instant now) {
        // return onExpiry == SESSION_ONLY_GRACE && now.isAfter(expiresAt) && now.isBefore(graceUntil);
        throw new UnsupportedOperationException("미구현");
    }

    /** 원 발급 기간. 연장 누적 상한(§03)을 계산하는 기준값이 된다. */
    public Duration originalDuration() {
        // 계보에서 ISSUED 이벤트를 찾아 그때의 (expiresAt - issuedAt) 를 돌려준다.
        // 현재 expiresAt 은 연장으로 밀려 있으므로 그대로 쓰면 안 된다.
        throw new UnsupportedOperationException("미구현");
    }

    /** 지금까지 연장으로 늘어난 총량. */
    public Duration totalExtendedBy() {
        throw new UnsupportedOperationException("미구현");
    }

    public void extend(Duration by, UUID approverId, String reason, boolean autoApproved) {
        // 1. 누적 상한 검사는 호출자(WarrantExtensionService)가 이미 했다고 가정하지 말고 여기서도 방어한다
        // 2. expiresAt = expiresAt.plus(by)
        // 3. lineage.add(EXTENDED 또는 AUTO_EXTENDED)
        throw new UnsupportedOperationException("미구현");
    }

    public void revoke(UUID actorId, String reason) {
        // revoked = true; state = REVOKED; lineage.add(REVOKED)
        // push 는 호출자가 한다. push 가 실패해도 revoked 는 남아야 하므로 순서를 바꾸지 말 것.
        throw new UnsupportedOperationException("미구현");
    }
}
