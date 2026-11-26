package io.seswar.warrant.warrant;

import io.seswar.warrant.approval.ApprovalService;
import io.seswar.warrant.approval.ApprovalService.SelfApprovalException;
import io.seswar.warrant.approval.Approver;
import io.seswar.warrant.approval.ApproverEligibility;
import io.seswar.warrant.identity.Subject;
import io.seswar.warrant.identity.SubjectRepository;
import io.seswar.warrant.policy.ExecRule;
import io.seswar.warrant.policy.Policy;
import io.seswar.warrant.policy.PolicyLinter;
import io.seswar.warrant.policy.PolicyRepository;
import io.seswar.warrant.policy.WriteRule;
import io.seswar.warrant.proto.WarrantProtos;
import io.seswar.warrant.signing.SigningKeyProvider;
import io.seswar.warrant.signing.WarrantSigner;
import io.seswar.warrant.warrant.WarrantExtensionService.CumulativeCapExceededException;
import io.seswar.warrant.warrant.WarrantExtensionService.Outcome;
import io.seswar.warrant.warrant.WarrantExtensionService.Result;
import io.seswar.warrant.warrant.api.IssueWarrantCommand;
import io.seswar.warrant.warrant.store.LineageType;
import io.seswar.warrant.warrant.store.OnExpiry;
import io.seswar.warrant.warrant.store.Warrant;
import io.seswar.warrant.warrant.store.WarrantLineage;
import io.seswar.warrant.warrant.store.WarrantLineageRepository;
import io.seswar.warrant.warrant.store.WarrantMode;
import io.seswar.warrant.warrant.store.WarrantRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.nio.file.Files;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

// Real PostgreSQL: the row lock and the lineage queries are part of what is tested. Each call commits for real.
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Transactional(propagation = Propagation.NOT_SUPPORTED)
@Testcontainers
@Import({WarrantExtensionService.class, ApprovalService.class, WarrantIssuanceService.class,
        WarrantRevocationService.class, WarrantSealer.class, WarrantProtoMapper.class, WarrantSigner.class,
        PolicyLinter.class, ApproverEligibility.class, WarrantExtensionServiceTest.Config.class})
class WarrantExtensionServiceTest {

    @Container
    @ServiceConnection
    static PostgreSQLContainer postgres = new PostgreSQLContainer("postgres:18");

    static final Duration THIRTY = Duration.ofMinutes(30);

    /** A clock the test moves by hand. */
    static class StepClock extends Clock {
        Instant now = Instant.parse("2026-11-24T09:00:00Z");

        void step(Duration d) {
            now = now.plus(d);
        }

        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
    }

    // An approver with no groups: enough for every policy without an approver group.
    private static Approver as(Subject s) {
        return new Approver(s.getId(), Set.of());
    }

    @TestConfiguration
    static class Config {
        @Bean
        StepClock clock() {
            return new StepClock();
        }

        @Bean
        SigningKeyProvider signingKeyProvider() throws Exception {
            return new SigningKeyProvider(Files.createTempDirectory("sk").resolve("signing.key").toString(), "central");
        }
    }

    @Autowired WarrantExtensionService extensions;
    @Autowired WarrantIssuanceService issuance;
    @Autowired ApprovalService approvals;
    @Autowired WarrantRevocationService revocation;
    @Autowired WarrantRepository warrants;
    @Autowired WarrantLineageRepository lineage;
    @Autowired SubjectRepository subjects;
    @Autowired PolicyRepository policies;
    @Autowired StepClock clock;

    Subject alice, bob;
    Policy readOnly, writes;
    String host;

    @BeforeEach
    void seed() {
        alice = subjects.saveAndFlush(Subject.of("oidc|" + UUID.randomUUID(), "alice-" + UUID.randomUUID(), "ec2-user",
                List.of("SHA256:a-" + UUID.randomUUID())));
        bob = subjects.saveAndFlush(Subject.of("oidc|" + UUID.randomUUID(), "bob-" + UUID.randomUUID(), "ec2-user",
                List.of("SHA256:b-" + UUID.randomUUID())));
        readOnly = policies.saveAndFlush(Policy.of("ro", false, List.of(new ExecRule("/usr/bin/ls")), List.of(), List.of()));
        writes = policies.saveAndFlush(Policy.of("rw", false, List.of(new ExecRule("/usr/bin/ls")),
                List.of(new WriteRule("/tmp", true, WriteRule.Effect.ALLOW)), List.of()));
        host = "node-" + UUID.randomUUID();
    }

    // Requested by alice, approved by bob: the normal path, so the lineage carries the original duration.
    Warrant issued(Policy p) {
        Warrant w = issuance.request(new IssueWarrantCommand(alice.getId(), "ec2-user", "INC-1", List.of(host),
                p.getId(), THIRTY, WarrantMode.DRYRUN, OnExpiry.DEMOTE, Duration.ZERO));
        clock.step(Duration.ofSeconds(1));
        Warrant approved = approvals.approve(w.getId(), as(bob));
        clock.step(Duration.ofSeconds(1));
        return approved;
    }

    Warrant reload(Warrant w) {
        return warrants.findById(w.getId()).orElseThrow();
    }

    List<LineageType> types(Warrant w) {
        return lineage.findByWarrantIdOrderByOccurredAtAsc(w.getId()).stream().map(WarrantLineage::getType).toList();
    }

    Result auto(Warrant w, Duration by) {
        Result r = extensions.requestAutomatically(w.getWarrantId(), host, "deploy.sh (pid 4821)", by);
        clock.step(Duration.ofSeconds(1));
        return r;
    }

    // ── 사람이 요청 · 승인 ────────────────────────────────────────────────────────

    @Test
    void 승인하면_만료만_미룬_새_revision이_다시_서명된다() throws Exception {
        Warrant w = issued(writes);
        Instant before = w.getExpiresAt();

        extensions.request(w.getId(), Duration.ofMinutes(15), alice.getId(), "배포 지연");
        clock.step(Duration.ofSeconds(1));
        Warrant x = extensions.approve(w.getId(), as(bob), null);

        assertThat(x.getExpiresAt()).isEqualTo(before.plus(Duration.ofMinutes(15)));
        assertThat(x.getRevision()).isEqualTo(2);
        WarrantProtos.Warrant signed = WarrantProtos.Warrant.parseFrom(reload(w).getSignedPayload());
        assertThat(signed.getRevision()).isEqualTo(2);
        assertThat(signed.getExpiresAtUnixNs())
                .isEqualTo(before.plus(Duration.ofMinutes(15)).getEpochSecond() * 1_000_000_000L
                        + before.plus(Duration.ofMinutes(15)).getNano());
        assertThat(types(w)).containsExactly(LineageType.REQUESTED, LineageType.ISSUED,
                LineageType.EXTENSION_REQUESTED, LineageType.EXTENDED);
        assertThat(extensions.openRequests()).noneMatch(r -> r.warrant().getId().equals(w.getId()));
    }

    @Test
    void 열린_요청은_승인_큐에_뜬다() {
        Warrant w = issued(writes);
        extensions.request(w.getId(), Duration.ofMinutes(15), alice.getId(), "배포 지연");

        assertThat(extensions.openRequests()).anySatisfy(r -> {
            assertThat(r.warrant().getId()).isEqualTo(w.getId());
            assertThat(r.request().getReason()).isEqualTo("배포 지연");
            assertThat(r.request().delta()).isEqualTo(Duration.ofMinutes(15));
        });
        assertThat(extensions.hasOpenRequest(w.getId())).isTrue();
    }

    @Test
    void 영장_주체_본인은_자기_연장을_승인할_수_없다() {
        Warrant w = issued(writes);
        extensions.request(w.getId(), Duration.ofMinutes(15), alice.getId(), "배포 지연");

        assertThatThrownBy(() -> extensions.approve(w.getId(), as(alice), null))
                .isInstanceOf(SelfApprovalException.class);
    }

    @Test
    void 영장_주체가_아니면_연장을_요청할_수_없다() {
        Warrant w = issued(writes);

        assertThatThrownBy(() -> extensions.request(w.getId(), Duration.ofMinutes(15), bob.getId(), "대신"))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void 열린_요청이_있으면_두_번째_요청은_중복이다() {
        Warrant w = issued(writes);
        extensions.request(w.getId(), Duration.ofMinutes(15), alice.getId(), "배포 지연");

        assertThatThrownBy(() -> extensions.request(w.getId(), Duration.ofMinutes(5), alice.getId(), "또"))
                .isInstanceOf(IllegalStateException.class);
        assertThat(auto(w, Duration.ofMinutes(5)).outcome()).isEqualTo(Outcome.DUPLICATE);
    }

    @Test
    void 화면에서_본_요청과_지금_열린_요청이_다르면_결정하지_않는다() {
        Warrant w = issued(writes);
        extensions.request(w.getId(), Duration.ofMinutes(15), alice.getId(), "배포 지연");

        assertThatThrownBy(() -> extensions.approve(w.getId(), as(bob), UUID.randomUUID()))
                .isInstanceOf(IllegalStateException.class);
        assertThat(reload(w).getRevision()).isEqualTo(1);
    }

    @Test
    void 같은_요청을_두_번_승인하면_두_번째는_409다() {
        Warrant w = issued(writes);
        extensions.request(w.getId(), Duration.ofMinutes(15), alice.getId(), "배포 지연");
        UUID req = extensions.openRequests().stream().filter(r -> r.warrant().getId().equals(w.getId()))
                .findFirst().orElseThrow().request().getId();
        extensions.approve(w.getId(), as(bob), req);

        assertThatThrownBy(() -> extensions.approve(w.getId(), as(bob), req))
                .isInstanceOf(IllegalStateException.class);
        assertThat(reload(w).getRevision()).isEqualTo(2);
    }

    @Test
    void 반려하면_계보에_남고_다시_요청할_수_있다() {
        Warrant w = issued(writes);
        extensions.request(w.getId(), Duration.ofMinutes(15), alice.getId(), "배포 지연");
        clock.step(Duration.ofSeconds(1));
        extensions.deny(w.getId(), as(bob), "작업 범위 밖", null);
        clock.step(Duration.ofSeconds(1));

        assertThat(reload(w).getRevision()).isEqualTo(1);
        assertThat(types(w)).endsWith(LineageType.EXTENSION_REQUESTED, LineageType.EXTENSION_DENIED);
        extensions.request(w.getId(), Duration.ofMinutes(5), alice.getId(), "다시");
        assertThat(extensions.hasOpenRequest(w.getId())).isTrue();
    }

    // ── 누적 상한 ────────────────────────────────────────────────────────────────

    @Test
    void 누적_상한_원_기간의_3배를_넘으면_연장이_아니라_새_신청이다() {
        Warrant w = issued(writes);

        assertThatThrownBy(() -> extensions.request(w.getId(), THIRTY.multipliedBy(3).plusSeconds(1), alice.getId(), "길게"))
                .isInstanceOf(CumulativeCapExceededException.class);

        extensions.request(w.getId(), THIRTY.multipliedBy(2), alice.getId(), "길게");
        clock.step(Duration.ofSeconds(1));
        extensions.approve(w.getId(), as(bob), null);
        clock.step(Duration.ofSeconds(1));

        assertThatThrownBy(() -> extensions.request(w.getId(), THIRTY.plusSeconds(1), alice.getId(), "더"))
                .isInstanceOf(CumulativeCapExceededException.class);
        assertThat(auto(w, THIRTY.plusSeconds(1)).outcome()).isEqualTo(Outcome.CAP_EXCEEDED);
        extensions.request(w.getId(), THIRTY, alice.getId(), "딱 상한까지");
    }

    // ── 연장할 수 없는 영장 ─────────────────────────────────────────────────────────

    @Test
    void 끝난_영장은_연장하지_않는다() {
        Warrant w = issued(writes);
        clock.step(THIRTY);

        assertThatThrownBy(() -> extensions.request(w.getId(), Duration.ofMinutes(5), alice.getId(), "늦음"))
                .isInstanceOf(IllegalStateException.class);
        assertThat(auto(w, Duration.ofMinutes(5)).outcome()).isEqualTo(Outcome.REJECTED);
    }

    @Test
    void 요청_뒤에_끝나면_승인할_수_없고_큐에서도_빠진다() {
        Warrant w = issued(writes);
        extensions.request(w.getId(), Duration.ofMinutes(15), alice.getId(), "배포 지연");
        clock.step(THIRTY);

        assertThatThrownBy(() -> extensions.approve(w.getId(), as(bob), null))
                .isInstanceOf(IllegalStateException.class);
        assertThat(extensions.openRequests()).noneMatch(r -> r.warrant().getId().equals(w.getId()));
    }

    @Test
    void 회수된_영장은_연장하지_않는다() {
        Warrant w = issued(readOnly);
        revocation.revoke(w.getId());

        assertThat(auto(w, Duration.ZERO).outcome()).isEqualTo(Outcome.REJECTED);
    }

    // ── warrantd 자동 요청 ──────────────────────────────────────────────────────

    @Test
    void 쓰기_규칙_없는_정책은_두_번까지_사람_없이_연장되고_근거가_남는다() {
        Warrant w = issued(readOnly);
        Instant before = w.getExpiresAt();

        Result first = auto(w, Duration.ZERO);
        Result second = auto(w, Duration.ZERO);
        Result third = auto(w, Duration.ZERO);

        assertThat(first.outcome()).isEqualTo(Outcome.AUTO_APPROVED);
        assertThat(first.warrant()).isNotNull();
        assertThat(second.outcome()).isEqualTo(Outcome.AUTO_APPROVED);
        assertThat(third.outcome()).isEqualTo(Outcome.PENDING_APPROVAL);
        assertThat(reload(w).getExpiresAt()).isEqualTo(before.plus(THIRTY.multipliedBy(2))); // 0 = 원 기간만큼
        List<WarrantLineage> auto = lineage.findByWarrantIdOrderByOccurredAtAsc(w.getId()).stream()
                .filter(l -> l.getType() == LineageType.AUTO_EXTENDED).toList();
        assertThat(auto).hasSize(2);
        assertThat(auto.get(1).getActorId()).isNull();
        assertThat(auto.get(1).getBasis()).contains("2회차");
        assertThat(auto.get(1).getReason()).isEqualTo("deploy.sh (pid 4821)");
    }

    @Test
    void 자동_연장도_원_기간의_2배를_넘기면_사람에게_간다() {
        Warrant w = issued(readOnly);

        assertThat(auto(w, THIRTY.multipliedBy(2).plusSeconds(1)).outcome()).isEqualTo(Outcome.PENDING_APPROVAL);
    }

    @Test
    void 쓰기_규칙이_있으면_언제나_사람이_승인한다() {
        Warrant w = issued(writes);

        Result r = auto(w, Duration.ofMinutes(10));

        assertThat(r.outcome()).isEqualTo(Outcome.PENDING_APPROVAL);
        assertThat(r.warrant()).isNull();
        assertThat(reload(w).getRevision()).isEqualTo(1);
        WarrantLineage req = extensions.openRequests().stream().filter(o -> o.warrant().getId().equals(w.getId()))
                .findFirst().orElseThrow().request();
        assertThat(req.getActorId()).isNull();
        assertThat(req.getBasis()).contains("deploy.sh (pid 4821)");
    }

    @Test
    void 다른_노드의_인증서로는_요청할_수_없다() {
        Warrant w = issued(readOnly);

        Result r = extensions.requestAutomatically(w.getWarrantId(), "other-" + host, "x", Duration.ZERO);

        assertThat(r.outcome()).isEqualTo(Outcome.REJECTED);
        assertThat(reload(w).getRevision()).isEqualTo(1);
    }

    @Test
    void 모르는_영장_번호는_거부한다() {
        assertThat(extensions.requestAutomatically(Long.MAX_VALUE, null, "x", Duration.ZERO).outcome())
                .isEqualTo(Outcome.REJECTED);
    }

    // 연장도 발급과 같은 승인 그룹을 따른다 — 연장이 그룹을 우회하는 뒷문이 되면 안 된다.
    @Test
    void 승인_그룹이_있는_정책의_연장은_그_그룹만_결정한다() {
        Policy db = policies.saveAndFlush(Policy.of("db", false, List.of(new ExecRule("/usr/bin/psql")), List.of(),
                List.of(), "warrant-approvers-db"));
        Warrant w = issuance.request(new IssueWarrantCommand(alice.getId(), "ec2-user", "INC-9", List.of(host),
                db.getId(), THIRTY, WarrantMode.DRYRUN, OnExpiry.DEMOTE, Duration.ZERO));
        clock.step(Duration.ofSeconds(1));
        assertThatThrownBy(() -> approvals.approve(w.getId(), as(bob)))
                .isInstanceOf(ApproverEligibility.NotEligibleApproverException.class);
        Approver dba = new Approver(bob.getId(), Set.of("warrant-approvers-db"));
        approvals.approve(w.getId(), dba);
        clock.step(Duration.ofSeconds(1));
        extensions.request(w.getId(), Duration.ofMinutes(10), alice.getId(), "마무리");

        assertThatThrownBy(() -> extensions.approve(w.getId(), as(bob), null))
                .isInstanceOf(ApproverEligibility.NotEligibleApproverException.class);
        assertThatThrownBy(() -> extensions.deny(w.getId(), as(bob), "아니다", null))
                .isInstanceOf(ApproverEligibility.NotEligibleApproverException.class);
        assertThat(extensions.approve(w.getId(), dba, null).getRevision()).isGreaterThan(1);
    }
}
