package io.seswar.warrant.approval;

import io.seswar.warrant.policy.Policy;
import io.seswar.warrant.policy.PolicyRepository;
import io.seswar.warrant.warrant.store.Warrant;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * 승인자 자격 — 정책이 승인 그룹을 정해 두었으면 그 그룹에 든 사람만 결정한다(발급 · 연장, 승인 · 반려 모두).
 * 조직도의 상급자가 아니라 「이 접근을 판단할 줄 아는 사람」이 승인한다는 뜻이다. 자기 승인 금지는 그대로 따로 걸린다.
 *
 * <p>정책 행은 불변이라 영장이 가리키는 정책의 그룹이 신청 뒤에 바뀌지 않는다.
 */
@Component
@RequiredArgsConstructor
public class ApproverEligibility {

    private final PolicyRepository policies;

    @ResponseStatus(HttpStatus.FORBIDDEN)
    public static class NotEligibleApproverException extends RuntimeException {
        NotEligibleApproverException(String displayId, String group) {
            super(displayId + " needs an approver in group " + group);
        }
    }

    /** 이 영장의 정책이 요구하는 승인 그룹. 없으면 null — 승인 역할이 있는 다른 사람 누구나. */
    public String requiredGroup(Warrant w) {
        return policies.findById(w.getPolicyId()).map(Policy::getApproverGroup).orElse(null);
    }

    public boolean eligible(Warrant w, Approver approver) {
        String group = requiredGroup(w);
        return group == null || approver.isIn(group);
    }

    // Called by ApprovalService and WarrantExtensionService before every decision.
    public void require(Warrant w, Approver approver) {
        String group = requiredGroup(w);
        if (group != null && !approver.isIn(group)) {
            throw new NotEligibleApproverException(w.getDisplayId(), group);
        }
    }
}
