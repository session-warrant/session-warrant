package io.seswar.warrant.approval;

import io.seswar.warrant.identity.CurrentSubject;
import io.seswar.warrant.warrant.Warrant;
import io.seswar.warrant.warrant.WarrantViews;
import io.seswar.warrant.warrant.push.WarrantPushService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

/**
 * 승인 큐 — 콘솔에서 신청 · 승인한다. 외부 메신저 연동은 두지 않는다.
 * 승인자 = 로그인한 사람. 본문에 승인자 id 를 받지 않는다. 승인은 커밋 뒤 대상 노드로 push 한다.
 */
@RestController
@RequestMapping("/api/approvals")
@RequiredArgsConstructor
public class ApprovalController {

    private final ApprovalService approvals;
    private final CurrentSubject current;
    private final WarrantViews views;
    private final WarrantPushService push;

    /** 본인 신청도 보이되 approvable=false 로 내린다. */
    public record QueueItem(WarrantViews.WarrantView warrant, boolean approvable) {
    }

    public record Decision(String reason) {
    }

    @GetMapping
    public List<QueueItem> queue(Authentication auth) {
        UUID me = current.require(auth).getId();
        return approvals.queue().stream()
                .map(w -> new QueueItem(views.of(w), !w.getSubjectId().equals(me)))
                .toList();
    }

    @PostMapping("/{id}/approve")
    public WarrantViews.WarrantView approve(@PathVariable UUID id, Authentication auth) {
        Warrant w = approvals.approve(id, current.require(auth).getId());
        push.push(w);
        return views.of(w);
    }

    @PostMapping("/{id}/reject")
    public WarrantViews.WarrantView reject(@PathVariable UUID id, @RequestBody Decision body, Authentication auth) {
        return views.of(approvals.reject(id, current.require(auth).getId(), body.reason()));
    }
}
