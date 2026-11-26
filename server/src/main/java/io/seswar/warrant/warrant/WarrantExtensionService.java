package io.seswar.warrant.warrant;

import io.seswar.warrant.approval.ApprovalService.SelfApprovalException;
import io.seswar.warrant.approval.Approver;
import io.seswar.warrant.approval.ApproverEligibility;
import io.seswar.warrant.policy.Policy;
import io.seswar.warrant.policy.PolicyRepository;
import io.seswar.warrant.warrant.store.LineageType;
import io.seswar.warrant.warrant.store.Warrant;
import io.seswar.warrant.warrant.store.WarrantLineage;
import io.seswar.warrant.warrant.store.WarrantLineageRepository;
import io.seswar.warrant.warrant.store.WarrantRepository;
import io.seswar.warrant.warrant.store.WarrantState;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * 연장 — <b>재로그인이 아니다</b>. 만료 시각만 바뀐 새 revision 을 push 하면 열린 세션이 그대로 이어진다(§03).
 *
 * <p><b>요청만 자동화하고 승인은 자동화하지 않는다.</b> 완전 자동 연장은
 * "활동이 있는 한 만료되지 않는 영장"이고, 공격자의 활동도 활동이다. 예외는 명시적 범위 하나뿐이다 —
 * 쓰기 규칙이 없는 정책의 warrantd 자동 요청은 정해진 횟수(기본 2회)까지, 연장 총량이 원 기간의 정해진 배수
 * (기본 2배) 안일 때만 사람 없이 승인한다. 그 사실과 근거는 계보(AUTO_EXTENDED · basis)에 남는다.
 *
 * <p><b>누적 상한은 예외가 없다.</b> 어떤 경로든 연장 총량이 원 기간의 정해진 배수(기본 3배)를 넘으면
 * 연장이 아니라 새 신청이다. 여기에 우회 경로를 만들면 시간 정책 전체가 무의미해진다.
 *
 * <p>연장 요청은 계보 한 줄(EXTENSION_REQUESTED)이고 영장당 열린 요청은 하나뿐이다. 열려 있는지는 계보에서
 * 센다: 요청 수가 결정(EXTENDED · EXTENSION_DENIED) 수보다 많으면 열려 있다. 자동 승인은 요청 줄 없이
 * AUTO_EXTENDED 한 줄만 남긴다 — 같은 시각의 두 줄은 순서가 정해지지 않아 세는 방식이 더 단단하다.
 *
 * <p>재서명까지 여기서 하고, push 는 커밋 뒤 호출자가 한다(발급 · 회수와 같다).
 */
@Service
@RequiredArgsConstructor
public class WarrantExtensionService {

    private final WarrantRepository warrants;
    private final WarrantLineageRepository lineage;
    private final PolicyRepository policies;
    private final WarrantSealer sealer;
    private final ApproverEligibility eligibility;
    private final Clock clock;

    // application.yml warrant.extension.* — the defaults here are the same values.
    @Value("${warrant.extension.cumulative-cap-multiplier:3}")
    int capMultiplier;
    @Value("${warrant.extension.auto-approve.enabled:true}")
    boolean autoApprove;
    @Value("${warrant.extension.auto-approve.max-count:2}")
    int autoMaxCount;
    @Value("${warrant.extension.auto-approve.max-total-multiplier:2}")
    int autoCapMultiplier;

    /** warrantd 요청의 결과. proto {@code ExtensionAck.Outcome} 과 같은 이름이다. */
    public enum Outcome { PENDING_APPROVAL, AUTO_APPROVED, DUPLICATE, CAP_EXCEEDED, REJECTED }

    /** warrant 는 AUTO_APPROVED 일 때만 — 호출자가 그걸 push 한다. */
    public record Result(Outcome outcome, String message, Warrant warrant) {
        static Result of(Outcome o, String message) {
            return new Result(o, message, null);
        }
    }

    /** 승인 큐에 뜨는 열린 연장 요청. */
    public record OpenRequest(Warrant warrant, WarrantLineage request) {
    }

    /** 누적 상한에 걸렸다 — 연장이 아니라 새 신청 대상. REST 에서는 409. */
    public static class CumulativeCapExceededException extends IllegalStateException {
        CumulativeCapExceededException(String message) {
            super(message);
        }
    }

    // ---------------------------------------------------------------- 요청

    /**
     * warrantd 의 T-5분 자동 요청. <b>이 단계는 전자동이어도 안전하다</b> — 요청일 뿐 권한이 늘지 않는다.
     *
     * @param peerHost 요청한 노드의 인증서 이름. 평문(로컬 개발)이면 null 이고 확인하지 않는다
     * @param by       0 이거나 없으면 원 기간만큼
     */
    @Transactional
    public Result requestAutomatically(long kernelWarrantId, String peerHost, String detectedWorkload, Duration by) {
        Instant now = clock.instant();
        Warrant w = warrants.findLockedByWarrantId(kernelWarrantId).orElse(null);
        if (w == null) {
            return Result.of(Outcome.REJECTED, "unknown warrant " + kernelWarrantId);
        }
        if (peerHost != null && !w.getTargetHosts().contains(peerHost)) {
            return Result.of(Outcome.REJECTED, "warrant " + w.getDisplayId() + " is not for " + peerHost);
        }
        try {
            w.requireExtendable(now);
        } catch (IllegalStateException e) {
            return Result.of(Outcome.REJECTED, e.getMessage());
        }

        History h = history(w);
        if (h.open() != null) {
            return Result.of(Outcome.DUPLICATE, "an extension request is already open for " + w.getDisplayId());
        }
        Duration extension = by == null || !by.isPositive() ? h.original() : by;
        if (!h.within(extension, capMultiplier)) {
            return Result.of(Outcome.CAP_EXCEEDED, capMessage(w, h));
        }
        String workload = detectedWorkload == null || detectedWorkload.isBlank() ? null : detectedWorkload.trim();

        if (autoApprovable(w, h, extension)) {
            int n = h.autoCount() + 1;
            w.extend(extension, now);
            sealer.seal(w);
            lineage.save(WarrantLineage.of(w.getId(), LineageType.AUTO_EXTENDED, now, null, workload, extension,
                    w.getExpiresAt()).basedOn("쓰기 규칙 없는 정책 자동 승인 " + n + "회차"));
            return new Result(Outcome.AUTO_APPROVED, "extended to " + w.getExpiresAt(), w);
        }

        lineage.save(WarrantLineage.of(w.getId(), LineageType.EXTENSION_REQUESTED, now, null, null, extension, null)
                .basedOn(workload == null ? "warrantd 자동 요청" : "warrantd: " + workload));
        return Result.of(Outcome.PENDING_APPROVAL, "waiting for an approver");
    }

    /** 영장 주체가 콘솔에서 직접 연장을 요청한다. 자동 요청과 같은 큐로 가고, 언제나 사람이 승인한다. */
    @Transactional
    public Warrant request(UUID warrantId, Duration by, UUID requesterId, String reason) {
        if (reason == null || reason.isBlank()) {
            throw new IllegalArgumentException("an extension request needs a reason");
        }
        if (by == null || !by.isPositive()) {
            throw new IllegalArgumentException("duration must be positive");
        }
        Warrant w = locked(warrantId);
        if (!w.getSubjectId().equals(requesterId)) {
            throw new AccessDeniedException("only the warrant's subject can ask to extend " + w.getDisplayId());
        }
        w.requireExtendable(clock.instant());
        History h = history(w);
        if (h.open() != null) {
            throw new IllegalStateException("an extension request is already open for " + w.getDisplayId());
        }
        if (!h.within(by, capMultiplier)) {
            throw new CumulativeCapExceededException(capMessage(w, h));
        }
        lineage.save(WarrantLineage.of(w.getId(), LineageType.EXTENSION_REQUESTED, clock.instant(), requesterId,
                reason.trim(), by, null));
        return w;
    }

    // ---------------------------------------------------------------- 결정

    /**
     * 사람이 승인하는 연장. 기본 경로다. 영장 주체 본인은 승인할 수 없다.
     *
     * @param requestLineageId 승인자가 화면에서 본 요청. 지금 열린 요청과 다르면 409 — 이중 클릭이나
     *                         두 승인자의 동시 클릭이 두 번 연장하지 않는다. null 이면 확인하지 않는다
     */
    @Transactional
    public Warrant approve(UUID warrantId, Approver approver, UUID requestLineageId) {
        Instant now = clock.instant();
        UUID approverId = approver.id();
        Warrant w = locked(warrantId);
        WarrantLineage open = decidable(w, approver, requestLineageId);
        History h = history(w);
        Duration by = open.delta();
        // The cap is checked again: other extensions may have landed since the request.
        if (!h.within(by, capMultiplier)) {
            throw new CumulativeCapExceededException(capMessage(w, h));
        }
        w.extend(by, now);
        sealer.seal(w);
        lineage.save(WarrantLineage.of(w.getId(), LineageType.EXTENDED, now, approverId, null, by, w.getExpiresAt()));
        return w;
    }

    @Transactional
    public Warrant deny(UUID warrantId, Approver approver, String reason, UUID requestLineageId) {
        if (reason == null || reason.isBlank()) {
            throw new IllegalArgumentException("a rejection needs a reason");
        }
        Warrant w = locked(warrantId);
        WarrantLineage open = decidable(w, approver, requestLineageId);
        lineage.save(WarrantLineage.of(w.getId(), LineageType.EXTENSION_DENIED, clock.instant(), approver.id(),
                reason.trim(), open.delta(), null));
        return w;
    }

    /** 승인 큐의 연장 칸. 끝났거나 회수된 영장의 요청은 결정할 게 없으므로 뺀다. */
    @Transactional(readOnly = true)
    public List<OpenRequest> openRequests() {
        Instant now = clock.instant();
        List<OpenRequest> out = new ArrayList<>();
        for (Warrant w : warrants.findByStateOrderByWarrantIdAsc(WarrantState.ISSUED)) {
            if (w.isRevoked() || w.isExpiredAt(now)) {
                continue;
            }
            WarrantLineage open = history(w).open();
            if (open != null) {
                out.add(new OpenRequest(w, open));
            }
        }
        return out;
    }

    /** 이 영장에 지금 열린 연장 요청이 있는가 — ApprovalController 가 승인 · 반려를 어느 쪽으로 보낼지 정한다. */
    @Transactional(readOnly = true)
    public boolean hasOpenRequest(UUID warrantId) {
        return warrants.findById(warrantId).map(w -> history(w).open() != null).orElse(false);
    }

    // ---------------------------------------------------------------- 규칙

    private Warrant locked(UUID warrantId) {
        return warrants.findLockedById(warrantId)
                .orElseThrow(() -> new IllegalArgumentException("unknown warrant " + warrantId));
    }

    private WarrantLineage decidable(Warrant w, Approver approver, UUID requestLineageId) {
        if (w.getSubjectId().equals(approver.id())) {
            throw new SelfApprovalException(w.getDisplayId());
        }
        eligibility.require(w, approver);
        w.requireExtendable(clock.instant());
        WarrantLineage open = history(w).open();
        if (open == null) {
            throw new IllegalStateException("no open extension request for " + w.getDisplayId());
        }
        if (requestLineageId != null && !requestLineageId.equals(open.getId())) {
            throw new IllegalStateException("the open extension request for " + w.getDisplayId()
                    + " is " + open.getId() + ", not " + requestLineageId);
        }
        return open;
    }

    // 쓰기 규칙이 하나라도 있으면(DENY 포함) 사람에게 넘긴다 — 판단을 단순하게 둔다.
    private boolean autoApprovable(Warrant w, History h, Duration extension) {
        Policy p = policies.findById(w.getPolicyId()).orElse(null);
        return autoApprove && p != null && p.getWriteRules().isEmpty()
                && h.autoCount() < autoMaxCount
                && h.within(extension, autoCapMultiplier);
    }

    private String capMessage(Warrant w, History h) {
        return "warrant " + w.getDisplayId() + " was already extended by " + h.extended()
                + "; the cap is " + capMultiplier + "x the original " + h.original() + " — request a new warrant";
    }

    private History history(Warrant w) {
        return History.of(w, lineage.findByWarrantIdOrderByOccurredAtAsc(w.getId()));
    }

    /**
     * 계보에서 읽은 연장 이력. original: 원 발급 기간 — 지금의 expiresAt 은 연장으로 밀려 있어 그대로 쓰면 안 된다.
     * extended: 연장으로 늘어난 총량. open: 열린 요청(없으면 null).
     */
    record History(Duration original, Duration extended, int autoCount, WarrantLineage open) {

        static History of(Warrant w, List<WarrantLineage> lines) {
            Duration extended = Duration.ZERO;
            int auto = 0, requests = 0, decisions = 0;
            Duration issued = null, requested = null;
            WarrantLineage lastRequest = null;
            for (WarrantLineage l : lines) {
                switch (l.getType()) {
                    case ISSUED -> issued = l.delta();
                    case REQUESTED -> requested = l.delta();
                    case EXTENSION_REQUESTED -> {
                        requests++;
                        lastRequest = l;
                    }
                    case EXTENDED -> {
                        decisions++;
                        extended = extended.plus(Objects.requireNonNullElse(l.delta(), Duration.ZERO));
                    }
                    case AUTO_EXTENDED -> {
                        auto++;
                        extended = extended.plus(Objects.requireNonNullElse(l.delta(), Duration.ZERO));
                    }
                    case EXTENSION_DENIED -> decisions++;
                    default -> { }
                }
            }
            Duration original = issued != null ? issued : requested != null ? requested
                    // Issued without the approval flow (tests, scripts): no lineage, so derive it.
                    : Duration.between(w.getIssuedAt(), w.getExpiresAt()).minus(extended);
            return new History(original, extended, auto, requests > decisions ? lastRequest : null);
        }

        /** 이번 연장을 더해도 연장 총량이 원 기간의 multiplier 배 이하인가. */
        boolean within(Duration additional, int multiplier) {
            return !extended.plus(additional).minus(original.multipliedBy(multiplier)).isPositive();
        }
    }
}
