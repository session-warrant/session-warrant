package io.seswar.warrant.warrant;

import io.seswar.warrant.signing.SigningKeyProvider;
import io.seswar.warrant.signing.WarrantSigner;
import io.seswar.warrant.policy.ExecRule;
import io.seswar.warrant.policy.NetRule;
import io.seswar.warrant.policy.Policy;
import io.seswar.warrant.policy.WriteRule;
import io.seswar.warrant.identity.Subject;
import io.seswar.warrant.warrant.OnExpiry;
import io.seswar.warrant.warrant.Warrant;
import io.seswar.warrant.warrant.WarrantMode;
import io.seswar.warrant.warrant.WarrantState;
import io.seswar.warrant.warrant.WarrantProtoMapper;
import io.seswar.warrant.proto.WarrantProtos;
import io.seswar.warrant.policy.PolicyRepository;
import io.seswar.warrant.identity.SubjectRepository;
import io.seswar.warrant.warrant.WarrantRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.nio.file.Files;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Testcontainers
@Import({WarrantIssuanceService.class, WarrantRevocationService.class, WarrantSealer.class,
        WarrantProtoMapper.class, WarrantSigner.class, WarrantIssuanceServiceTest.Fixed.class})
class WarrantIssuanceServiceTest {

    @Container
    @ServiceConnection
    static PostgreSQLContainer postgres = new PostgreSQLContainer("postgres:18");

    static final Instant T = Instant.parse("2026-11-08T00:00:00Z");

    @TestConfiguration
    static class Fixed {
        @Bean
        Clock clock() {
            return Clock.fixed(T, ZoneOffset.UTC);
        }

        @Bean
        SigningKeyProvider signingKeyProvider() throws Exception {
            return new SigningKeyProvider(Files.createTempDirectory("sk").resolve("signing.key").toString(), "central");
        }
    }

    @Autowired WarrantIssuanceService issuance;
    @Autowired WarrantRevocationService revocation;
    @Autowired WarrantSigner signer;
    @Autowired SubjectRepository subjects;
    @Autowired PolicyRepository policies;
    @Autowired WarrantRepository warrants;

    Subject alice;
    Policy policy;

    @BeforeEach
    void seed() {
        alice = subjects.saveAndFlush(Subject.of("oidc|" + UUID.randomUUID(), "alice@example.com", "ec2-user",
                List.of("SHA256:alice-" + UUID.randomUUID())));
        policy = policies.saveAndFlush(Policy.of("ops", false,
                List.of(new ExecRule("/usr/bin/ls"), new ExecRule("/usr/bin/bash")),
                List.of(new WriteRule("/tmp", true, WriteRule.Effect.ALLOW), new WriteRule("/etc", true, WriteRule.Effect.DENY)),
                List.of(new NetRule("10.0.0.0/8", 443, NetRule.Proto.TCP))));
    }

    IssueWarrantCommand command(List<String> hosts, Duration d) {
        return new IssueWarrantCommand(alice.getId(), "ec2-user", "INC-1 장애 대응", hosts, policy.getId(),
                d, WarrantMode.DRYRUN, OnExpiry.DEMOTE, Duration.ZERO);
    }

    @Test
    void 발급하면_커널_id와_revision_1과_서명이_붙는다() {
        Warrant w = issuance.issue(command(List.of("node-1"), Duration.ofMinutes(30)));

        assertThat(w.getWarrantId()).isPositive();
        assertThat(w.getRevision()).isEqualTo(1);
        assertThat(w.getState()).isEqualTo(WarrantState.ISSUED);
        assertThat(w.getExpiresAt()).isEqualTo(T.plus(Duration.ofMinutes(30)));
        assertThat(w.getSigningKeyId()).isEqualTo("central");
        assertThat(signer.verify(w.getSignedPayload(), w.getSignature())).isTrue();
    }

    // 노드는 서명된 바이트만 받는다. 그 안에 세션에 붙이고 판정하는 데 필요한 게 다 있어야 한다.
    @Test
    void 서명된_바이트에_노드가_쓰는_값이_전부_들어간다() throws Exception {
        Warrant w = issuance.issue(command(List.of("node-1", "node-2"), Duration.ofMinutes(30)));

        WarrantProtos.Warrant p = WarrantProtos.Warrant.parseFrom(w.getSignedPayload());
        assertThat(p.getWarrantId()).isEqualTo(w.getWarrantId());
        assertThat(p.getRevision()).isEqualTo(1);
        assertThat(p.getSubjectId()).isEqualTo(alice.getKernelSubjectId());
        assertThat(p.getPrincipal()).isEqualTo("alice@example.com");
        assertThat(p.getLoginAccount()).isEqualTo("ec2-user");
        assertThat(p.getSshKeyFingerprintsList()).containsExactlyElementsOf(alice.getSshKeyFingerprints());
        assertThat(p.getTargetHostsList()).containsExactly("node-1", "node-2");
        assertThat(p.getExpiresAtUnixNs()).isEqualTo(T.plus(Duration.ofMinutes(30)).getEpochSecond() * 1_000_000_000L);
        assertThat(p.getMode()).isEqualTo(WarrantProtos.Mode.MODE_DRYRUN);
        assertThat(p.getRevoked()).isFalse();
        assertThat(p.getPolicyId()).isEqualTo(policy.getKernelPolicyId());
        assertThat(p.getPolicy().getExecRulesList()).extracting(WarrantProtos.ExecRule::getPath)
                .containsExactly("/usr/bin/bash", "/usr/bin/ls");
        assertThat(p.getPolicy().getWriteRulesList()).extracting(WarrantProtos.WriteRule::getEffect)
                .containsExactly(WarrantProtos.WriteRule.Effect.EFFECT_DENY, WarrantProtos.WriteRule.Effect.EFFECT_ALLOW);
        assertThat(p.getPolicy().getNetRules(0).getCidr()).isEqualTo("10.0.0.0/8");
        assertThat(p.getPolicy().getNetRules(0).getProto()).isEqualTo(WarrantProtos.Proto.PROTO_TCP);
    }

    // 노드는 같은 policy_id 의 규칙이 영장마다 다르면 거부한다. 같은 정책이면 바이트도 같아야 한다.
    @Test
    void 같은_정책을_쓰는_영장들의_정책_바이트는_같다() throws Exception {
        Warrant a = issuance.issue(command(List.of("node-1"), Duration.ofMinutes(30)));
        Warrant b = issuance.issue(command(List.of("node-1"), Duration.ofMinutes(30)));

        assertThat(WarrantProtos.Warrant.parseFrom(a.getSignedPayload()).getPolicy())
                .isEqualTo(WarrantProtos.Warrant.parseFrom(b.getSignedPayload()).getPolicy());
    }

    @Test
    void 영장마다_커널_id가_다르다() {
        Warrant a = issuance.issue(command(List.of("node-1"), Duration.ofMinutes(30)));
        Warrant b = issuance.issue(command(List.of("node-1"), Duration.ofMinutes(30)));

        assertThat(a.getWarrantId()).isNotEqualTo(b.getWarrantId());
    }

    @Test
    void 없는_주체나_정책으로는_발급하지_않는다() {
        IssueWarrantCommand noSubject = new IssueWarrantCommand(UUID.randomUUID(), "ec2-user", "r", List.of("node-1"),
                policy.getId(), Duration.ofMinutes(30), WarrantMode.DRYRUN, OnExpiry.DEMOTE, Duration.ZERO);
        IssueWarrantCommand noPolicy = new IssueWarrantCommand(alice.getId(), "ec2-user", "r", List.of("node-1"),
                UUID.randomUUID(), Duration.ofMinutes(30), WarrantMode.DRYRUN, OnExpiry.DEMOTE, Duration.ZERO);

        assertThatThrownBy(() -> issuance.issue(noSubject)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> issuance.issue(noPolicy)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void 기간이_없거나_대상_호스트가_없으면_발급하지_않는다() {
        assertThatThrownBy(() -> issuance.issue(command(List.of("node-1"), Duration.ZERO)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> issuance.issue(command(List.of(), Duration.ofMinutes(30))))
                .isInstanceOf(IllegalArgumentException.class);
    }

    // 취소도 새 revision 의 서명 봉투로 내려간다 — 노드는 더 큰 revision 만 받는다.
    @Test
    void 취소하면_revision이_오르고_취소된_내용으로_다시_서명된다() throws Exception {
        Warrant w = issuance.issue(command(List.of("node-1"), Duration.ofMinutes(30)));

        Warrant r = revocation.revoke(w.getId());

        assertThat(r.getRevision()).isEqualTo(2);
        assertThat(r.getState()).isEqualTo(WarrantState.REVOKED);
        WarrantProtos.Warrant p = WarrantProtos.Warrant.parseFrom(r.getSignedPayload());
        assertThat(p.getRevoked()).isTrue();
        assertThat(p.getRevision()).isEqualTo(2);
        assertThat(p.getWarrantId()).isEqualTo(w.getWarrantId());
        assertThat(signer.verify(r.getSignedPayload(), r.getSignature())).isTrue();
    }

    @Test
    void 대상_호스트의_살아_있는_영장만_고른다() {
        Warrant mine = issuance.issue(command(List.of("node-a"), Duration.ofMinutes(30)));
        issuance.issue(command(List.of("node-b"), Duration.ofMinutes(30)));
        Warrant revoked = issuance.issue(command(List.of("node-a"), Duration.ofMinutes(30)));
        revocation.revoke(revoked.getId());
        Warrant shortLived = issuance.issue(command(List.of("node-a"), Duration.ofMinutes(5)));

        assertThat(warrants.findActiveForHost("node-a", T.plus(Duration.ofMinutes(10))))
                .extracting(Warrant::getId)
                .containsExactly(mine.getId())
                .doesNotContain(shortLived.getId());
        assertThat(Set.copyOf(warrants.findActiveForHost("node-a", T).stream().map(Warrant::getId).toList()))
                .containsExactlyInAnyOrder(mine.getId(), shortLived.getId());
    }
}
