package io.seswar.warrant.api;

import io.seswar.warrant.application.IssueWarrantCommand;
import io.seswar.warrant.application.WarrantIssuanceService;
import io.seswar.warrant.application.WarrantPushService;
import io.seswar.warrant.application.WarrantRevocationService;
import io.seswar.warrant.domain.warrant.OnExpiry;
import io.seswar.warrant.domain.warrant.Warrant;
import io.seswar.warrant.domain.warrant.WarrantMode;
import io.seswar.warrant.domain.warrant.WarrantState;
import io.seswar.warrant.repository.WarrantRepository;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * 영장 발급 · 조회 · 회수. <b>지금은 승인 없이 바로 발급한다</b> (단순 CRUD 단계).
 * 발급 · 회수는 트랜잭션이 커밋된 뒤 push 한다 — push 먼저 하고 저장이 실패하면 노드에만 있는 유령 영장이 생긴다.
 *
 * <p>만료를 여기서 "실행"하는 엔드포인트를 만들지 말 것. 만료는 커널이 시각 비교로 스스로 발효시킨다(§05).
 * 아직 없는 것: 승인(/api/approvals), 연장, 계보 조회.
 */
@RestController
@RequestMapping("/api/warrants")
@RequiredArgsConstructor
public class WarrantController {

    private final WarrantIssuanceService issuance;
    private final WarrantRevocationService revocation;
    private final WarrantPushService push;
    private final WarrantRepository warrants;

    @Value("${warrant.default-duration}")
    private Duration defaultDuration;

    public record IssueRequest(@NotNull UUID subjectId, @NotBlank String loginAccount, @NotBlank String reason,
                               @NotEmpty List<String> targetHosts, @NotNull UUID policyId,
                               Duration duration, WarrantMode mode, OnExpiry onExpiry) {
    }

    public record WarrantView(UUID id, long warrantId, String displayId, int revision, WarrantState state,
                              UUID subjectId, String loginAccount, List<String> sshKeyFingerprints,
                              List<String> targetHosts, UUID policyId, String reason, WarrantMode mode,
                              OnExpiry onExpiry, Instant issuedAt, Instant expiresAt, boolean revoked) {
        static WarrantView of(Warrant w) {
            return new WarrantView(w.getId(), w.getWarrantId(), w.getDisplayId(), w.getRevision(), w.getState(),
                    w.getSubjectId(), w.getLoginAccount(), w.getSshKeyFingerprints().stream().sorted().toList(),
                    w.getTargetHosts().stream().sorted().toList(), w.getPolicyId(), w.getReason(), w.getMode(),
                    w.getOnExpiry(), w.getIssuedAt(), w.getExpiresAt(), w.isRevoked());
        }
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public WarrantView issue(@Valid @RequestBody IssueRequest body) {
        Warrant w = issuance.issue(new IssueWarrantCommand(body.subjectId(), body.loginAccount(), body.reason(),
                body.targetHosts(), body.policyId(),
                body.duration() == null ? defaultDuration : body.duration(),
                body.mode() == null ? WarrantMode.OBSERVE : body.mode(),
                body.onExpiry(), Duration.ZERO));
        push.push(w);
        return WarrantView.of(w);
    }

    @GetMapping
    public List<WarrantView> list() {
        return warrants.findAllByOrderByIssuedAtDesc().stream().map(WarrantView::of).toList();
    }

    @GetMapping("/{id}")
    public WarrantView get(@PathVariable UUID id) {
        return warrants.findById(id).map(WarrantView::of)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "unknown warrant " + id));
    }

    /** 회수. 새 revision(revoked=true)으로 다시 서명해 push 한다. 이미 취소된 영장이면 그대로 돌려준다. */
    @DeleteMapping("/{id}")
    public WarrantView revoke(@PathVariable UUID id) {
        Warrant w = revocation.revoke(id);
        push.push(w);
        return WarrantView.of(w);
    }
}
