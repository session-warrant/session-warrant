package io.seswar.warrant.warrant;

import io.seswar.warrant.warrant.IssueWarrantCommand;
import io.seswar.warrant.warrant.WarrantIssuanceService;
import io.seswar.warrant.identity.CurrentSubject;
import io.seswar.warrant.warrant.WarrantViews.WarrantView;
import io.seswar.warrant.warrant.push.WarrantPushService;
import org.springframework.security.core.Authentication;
import io.seswar.warrant.warrant.WarrantRevocationService;
import io.seswar.warrant.warrant.OnExpiry;
import io.seswar.warrant.warrant.Warrant;
import io.seswar.warrant.warrant.WarrantMode;
import io.seswar.warrant.warrant.WarrantState;
import io.seswar.warrant.warrant.WarrantRepository;
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
 * 영장 신청 · 조회 · 회수. 신청은 승인 큐로 가고(approval), 다른 사람이 승인해야 서명 · push 된다.
 * 신청자는 로그인한 사람이다 — 본문의 이름을 믿지 않는다.
 * 회수는 트랜잭션이 커밋된 뒤 push 한다 — push 먼저 하고 저장이 실패하면 노드와 서버가 어긋난다.
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
    private final WarrantViews views;
    private final CurrentSubject current;

    @Value("${warrant.default-duration}")
    private Duration defaultDuration;

    public record IssueRequest(@NotBlank String loginAccount, @NotBlank String reason,
                               @NotEmpty List<String> targetHosts, @NotNull UUID policyId,
                               Duration duration, WarrantMode mode, OnExpiry onExpiry) {
    }


    /** 신청. 승인 큐로 간다 — 아직 서명도 push 도 없다. */
    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public WarrantView request(@Valid @RequestBody IssueRequest body, Authentication auth) {
        Warrant w = issuance.request(new IssueWarrantCommand(current.require(auth).getId(), body.loginAccount(), body.reason(),
                body.targetHosts(), body.policyId(),
                body.duration() == null ? defaultDuration : body.duration(),
                body.mode() == null ? WarrantMode.OBSERVE : body.mode(),
                body.onExpiry(), Duration.ZERO));
        return views.of(w);
    }

    @GetMapping
    public List<WarrantView> list() {
        return warrants.findAllByOrderByIssuedAtDesc().stream().map(views::of).toList();
    }

    @GetMapping("/{id}")
    public WarrantView get(@PathVariable UUID id) {
        return warrants.findById(id).map(views::of)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "unknown warrant " + id));
    }

    /** 회수. 새 revision(revoked=true)으로 다시 서명해 push 한다. 발급된(ISSUED) 영장만 — 아니면 409. */
    @DeleteMapping("/{id}")
    public WarrantView revoke(@PathVariable UUID id, Authentication auth) {
        Warrant w = revocation.revoke(id, current.require(auth).getId());
        push.push(w);
        return views.of(w);
    }
}
