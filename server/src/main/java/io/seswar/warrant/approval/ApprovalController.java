package io.seswar.warrant.approval;

import io.seswar.warrant.warrant.WarrantExtensionService;
import io.seswar.warrant.warrant.api.WarrantViews;
import io.seswar.warrant.warrant.store.Warrant;
import io.seswar.warrant.warrant.store.WarrantLineage;
import io.seswar.warrant.identity.CurrentSubject;
import io.seswar.warrant.identity.Subject;
import io.seswar.warrant.identity.SubjectRepository;
import io.seswar.warrant.policy.PolicyLintFinding;
import io.seswar.warrant.policy.PolicyLinter;
import io.seswar.warrant.policy.PolicyRepository;
import io.seswar.warrant.warrant.push.WarrantPushService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * 승인 큐 — 콘솔에서 신청 · 승인한다. 외부 메신저 연동은 두지 않는다.
 * 승인자 = 로그인한 사람. 본문에 승인자 id 를 받지 않는다. 승인은 커밋 뒤 대상 노드로 push 한다.
 *
 * <p>발급 대기와 열린 연장 요청이 한 큐 · 한 엔드포인트를 쓴다. 영장이 아직 REQUESTED 면 발급 결정,
 * 발급된 영장에 열린 연장 요청이 있으면 연장 결정이다.
 */
@RestController
@RequestMapping("/api/approvals")
@RequiredArgsConstructor
public class ApprovalController {

    private final ApprovalService approvals;
    private final WarrantExtensionService extensions;
    private final CurrentSubject current;
    private final WarrantViews views;
    private final WarrantPushService push;
    private final PolicyRepository policies;
    private final PolicyLinter linter;
    private final SubjectRepository subjects;

    public enum Kind { ISSUE, EXTENSION }

    /**
     * 본인 신청도 보이되 approvable=false 로 내린다(연장은 영장 주체 본인이 승인할 수 없다).
     * {@code policyWarnings} 는 정책 lint 의 WARN — 막지는 않고 승인자가 보고 판단한다(ERROR 는 신청 때 이미 걸렀다).
     * {@code extension} 은 kind=EXTENSION 일 때만.
     */
    public record QueueItem(Kind kind, WarrantViews.WarrantView warrant, boolean approvable,
                            List<PolicyLintFinding> policyWarnings, ExtensionView extension) {
    }

    /**
     * 열린 연장 요청. requestLineageId 를 승인 · 반려 본문에 되돌려 보내면 그 요청이 아직 열려 있을 때만 결정된다.
     * requestedBy 가 null 이면 warrantd 의 자동 요청이고, 근거(감지한 작업)는 basis 에 있다.
     */
    public record ExtensionView(UUID requestLineageId, Long requestedSeconds, Instant requestedAt,
                                String requestedBy, String reason, String basis) {
    }

    /** reason 은 반려에만 필요하다. requestLineageId 는 연장 결정에서만 본다(없으면 확인하지 않는다). */
    public record Decision(String reason, UUID requestLineageId) {
    }

    @GetMapping
    public List<QueueItem> queue(@RequestParam(required = false) Kind kind, Authentication auth) {
        UUID me = current.require(auth).getId();
        List<QueueItem> out = new ArrayList<>();
        if (kind == null || kind == Kind.ISSUE) {
            for (Warrant w : approvals.queue()) {
                out.add(new QueueItem(Kind.ISSUE, views.of(w), !w.getSubjectId().equals(me), warnings(w), null));
            }
        }
        if (kind == null || kind == Kind.EXTENSION) {
            for (WarrantExtensionService.OpenRequest r : extensions.openRequests()) {
                Warrant w = r.warrant();
                out.add(new QueueItem(Kind.EXTENSION, views.of(w), !w.getSubjectId().equals(me), warnings(w),
                        extensionView(r.request())));
            }
        }
        return out;
    }

    @PostMapping("/{id}/approve")
    public WarrantViews.WarrantView approve(@PathVariable UUID id, @RequestBody(required = false) Decision body,
                                            Authentication auth) {
        UUID me = current.require(auth).getId();
        Warrant w = extensions.hasOpenRequest(id)
                ? extensions.approve(id, me, body == null ? null : body.requestLineageId())
                : approvals.approve(id, me);
        push.push(w);
        return views.of(w);
    }

    @PostMapping("/{id}/reject")
    public WarrantViews.WarrantView reject(@PathVariable UUID id, @RequestBody Decision body, Authentication auth) {
        UUID me = current.require(auth).getId();
        return views.of(extensions.hasOpenRequest(id)
                ? extensions.deny(id, me, body.reason(), body.requestLineageId())
                : approvals.reject(id, me, body.reason()));
    }

    private List<PolicyLintFinding> warnings(Warrant w) {
        return policies.findById(w.getPolicyId()).map(linter::warnings).orElse(List.of());
    }

    private ExtensionView extensionView(WarrantLineage l) {
        String by = l.getActorId() == null ? null
                : subjects.findById(l.getActorId()).map(Subject::getPrincipal).orElse(null);
        return new ExtensionView(l.getId(), l.getDeltaSeconds(), l.getOccurredAt(), by, l.getReason(), l.getBasis());
    }
}
