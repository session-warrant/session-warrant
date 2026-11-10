package io.seswar.warrant.warrant;

import io.seswar.warrant.policy.Policy;
import io.seswar.warrant.identity.Subject;
import io.seswar.warrant.warrant.OnExpiry;
import io.seswar.warrant.warrant.Warrant;
import io.seswar.warrant.policy.PolicyRepository;
import io.seswar.warrant.identity.SubjectRepository;
import io.seswar.warrant.warrant.WarrantRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;

/**
 * 영장의 T0. {@link #request} 는 신청(REQUESTED)만 저장하고, 서명 · push 는 다른 사람이 승인할 때
 * (approval.ApprovalService) 한다. {@link #issue} 는 승인 없이 바로 발급한다 — 테스트 · 내부용이다.
 *
 * <p>설계상 남은 것: PolicyLinter, (subject, 호스트, loginAccount) 활성 1개 불변식, 재발급.
 */
@Service
@RequiredArgsConstructor
public class WarrantIssuanceService {

    private final WarrantRepository warrants;
    private final SubjectRepository subjects;
    private final PolicyRepository policies;
    private final WarrantSealer sealer;
    private final WarrantLineageRepository lineage;
    private final Clock clock;

    /** 신청. 신청자 = 영장의 주체(로그인한 사람). 노드로는 아무것도 내려가지 않는다. */
    @Transactional
    public Warrant request(IssueWarrantCommand cmd) {
        Subject subject = subjects.findById(cmd.subjectId())
                .orElseThrow(() -> new IllegalArgumentException("unknown subject " + cmd.subjectId()));
        Policy policy = policies.findById(cmd.policyId())
                .orElseThrow(() -> new IllegalArgumentException("unknown policy " + cmd.policyId()));
        validate(cmd);
        Warrant w = warrants.saveAndFlush(Warrant.request(subject, policy, cmd.loginAccount(), cmd.reason(),
                cmd.targetHosts(), clock.instant(), cmd.duration(), cmd.mode(), onExpiry(cmd)));
        lineage.save(WarrantLineage.of(w.getId(), LineageType.REQUESTED, clock.instant(), subject.getId(),
                cmd.reason(), cmd.duration(), null));
        return w;
    }

    @Transactional
    public Warrant issue(IssueWarrantCommand cmd) {
        Subject subject = subjects.findById(cmd.subjectId())
                .orElseThrow(() -> new IllegalArgumentException("unknown subject " + cmd.subjectId()));
        Policy policy = policies.findById(cmd.policyId())
                .orElseThrow(() -> new IllegalArgumentException("unknown policy " + cmd.policyId()));
        validate(cmd);

        // The kernel id comes from the DB sequence on insert, and the signed bytes must contain it.
        Warrant w = warrants.saveAndFlush(Warrant.issue(subject, policy, cmd.loginAccount(), cmd.reason(),
                cmd.targetHosts(), clock.instant(), cmd.duration(), cmd.mode(), onExpiry(cmd)));
        sealer.seal(w);
        return w;
    }

    private static void validate(IssueWarrantCommand cmd) {
        if (cmd.duration() == null || !cmd.duration().isPositive()) {
            throw new IllegalArgumentException("duration must be positive");
        }
        if (cmd.targetHosts() == null || cmd.targetHosts().isEmpty()) {
            throw new IllegalArgumentException("targetHosts is empty");
        }
    }

    private static OnExpiry onExpiry(IssueWarrantCommand cmd) {
        return cmd.onExpiry() == null ? OnExpiry.DEMOTE : cmd.onExpiry();
    }
}
