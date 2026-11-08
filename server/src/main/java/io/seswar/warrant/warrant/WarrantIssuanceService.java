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
 * 영장의 T0 · 발급(§11). <b>지금은 승인 없이 바로 발급한다</b> — 단순 CRUD 단계다.
 * 저장 → 커널 id 받기 → 서명 순서로 가고, push 는 커밋 뒤 호출자(WarrantController)가 한다.
 *
 * <p>설계상 남은 것 (README 「신청 · 승인」): REQUESTED → 승인 → ISSUED 흐름, PolicyLinter,
 * (subject, 호스트, loginAccount) 활성 1개 불변식, 계보, 재발급.
 */
@Service
@RequiredArgsConstructor
public class WarrantIssuanceService {

    private final WarrantRepository warrants;
    private final SubjectRepository subjects;
    private final PolicyRepository policies;
    private final WarrantSealer sealer;
    private final Clock clock;

    @Transactional
    public Warrant issue(IssueWarrantCommand cmd) {
        Subject subject = subjects.findById(cmd.subjectId())
                .orElseThrow(() -> new IllegalArgumentException("unknown subject " + cmd.subjectId()));
        Policy policy = policies.findById(cmd.policyId())
                .orElseThrow(() -> new IllegalArgumentException("unknown policy " + cmd.policyId()));
        if (cmd.duration() == null || !cmd.duration().isPositive()) {
            throw new IllegalArgumentException("duration must be positive");
        }
        if (cmd.targetHosts() == null || cmd.targetHosts().isEmpty()) {
            throw new IllegalArgumentException("targetHosts is empty");
        }
        OnExpiry onExpiry = cmd.onExpiry() == null ? OnExpiry.DEMOTE : cmd.onExpiry();

        // The kernel id comes from the DB sequence on insert, and the signed bytes must contain it.
        Warrant w = warrants.saveAndFlush(Warrant.issue(subject, policy, cmd.loginAccount(), cmd.reason(),
                cmd.targetHosts(), clock.instant(), cmd.duration(), cmd.mode(), onExpiry));
        sealer.seal(w);
        return w;
    }
}
