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
 *     __u64 grace_ns;     // on_expiry=2 일 때 유예 기간 (만료 뒤 추가 시간)
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

    /** 서버 PK. proto {@code warrant_uuid}. 커널로 안 내려간다. */
    private UUID id;

    /**
     * 커널 맵 키 (proto {@code warrant_id}, u64). 서버가 시퀀스로 발급하고 <b>재사용하지 않는다</b> —
     * 재사용하면 과거 감사 로그의 귀속이 조용히 뒤바뀐다. 0 은 "무영장" 자리라 발급하지 않는다.
     * revision 이 올라도 불변.
     */
    private long warrantId;

    /** 발급 1, 연장 · 취소마다 +1. 노드는 자기가 가진 것보다 큰 revision 만 적용한다(재생 방어). */
    private int revision;

    /** 사람이 읽는 식별자. 예: {@code W-4821-3F}. Slack · 감사 리포트에 나온다. */
    private String displayId;

    /** 주체. {@code subject_id} 로 커널에 내려간다. */
    private UUID subjectId;

    /**
     * PAM 바인딩 키 (proto {@code login_account}). 예: {@code ec2-user}. 신원이 아니다 — 신원은 subject.
     * <b>(subject, 대상 호스트, loginAccount) 당 활성 영장은 1개</b>(서버 불변식, proto/README 미해결 1).
     */
    private String loginAccount;

    /**
     * 발급 시점의 {@code Subject.sshKeyFingerprints} 스냅샷. 영장과 함께 서명된다.
     * 사후에 키가 추가 · 폐기돼도 이미 서명된 영장은 바뀌지 않는다 — 바꾸려면 새 revision.
     * 비어 있으면 어떤 세션에도 붙지 않는다(와일드카드 아님).
     */
    private List<String> sshKeyFingerprints;

    /**
     * 정책 <b>버전</b> 행. 커널로는 그 행의 {@code kernelPolicyId}(u32)가 {@code policy_id} 로 내려가
     * rule_exec · rule_write · rule_net 조회 키의 앞부분이 된다. 정책은 영장에 인라인으로 서명된다.
     */
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

    /**
     * 유예 <b>기간</b> (proto {@code grace_window_ns}). SESSION_ONLY_GRACE 에서만 의미가 있고 0 = 유예 없음.
     * 절대시각이 아니라 기간인 이유: 연장으로 expiresAt 이 밀리면 유예 창도 따라가야 한다.
     * 무기한은 허용되지 않는다. 유예 종료 시각은 {@link #graceUntil()} 로 파생한다.
     */
    private Duration graceWindow;

    private WarrantMode mode;

    private OnExpiry onExpiry;

    private WarrantState state;

    /** 취소 플래그. 커널에서는 1바이트이고, 뒤집는 순간 전 노드에서 즉시 발효된다. */
    private boolean revoked;

    /**
     * 자기보호(§16)를 풀 수 있는 유일한 영장. 일반 발급 경로({@code IssueWarrantCommand})로는 못 켠다.
     * 노드는 이 플래그가 켜진 봉투를 받는 즉시 최고 등급 경보를 올린다.
     */
    private boolean breakGlass;

    /**
     * <b>현재 revision</b> 의 서명된 protobuf 바이트. JSON 이 아니라 이 바이트에 서명한다.
     * 재직렬화하지 말고 이 바이트 그대로 push 한다 — 재직렬화하면 서명이 깨진다.
     */
    private byte[] signedPayload;

    private byte[] signature;

    /** 서명 키 id (proto {@code SignedWarrant.key_id}). 키 교체 중 공존하는 두 키를 가른다. */
    private String signingKeyId;

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
        // return onExpiry == SESSION_ONLY_GRACE && now.isAfter(expiresAt) && now.isBefore(graceUntil());
        throw new UnsupportedOperationException("미구현");
    }

    /** 유예 종료 시각. 저장하지 않는 파생값 — expiresAt + graceWindow. */
    public Instant graceUntil() {
        // return expiresAt.plus(graceWindow);
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
        // 2. expiresAt = expiresAt.plus(by), revision++
        // 3. lineage.add(EXTENDED 또는 AUTO_EXTENDED)
        // 4. 재서명은 호출자가 한다 — 새 revision 의 signedPayload 가 나와야 push 할 수 있다
        throw new UnsupportedOperationException("미구현");
    }

    public void revoke(UUID actorId, String reason) {
        // revoked = true; revision++; state = REVOKED; lineage.add(REVOKED)
        // 취소도 새 revision 의 서명 봉투로 내려간다 — "취소만 서명 검증을 안 한다" 같은 구멍을 막는다
        // push 는 호출자가 한다. push 가 실패해도 revoked 는 남아야 하므로 순서를 바꾸지 말 것.
        throw new UnsupportedOperationException("미구현");
    }
}
