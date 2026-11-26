package io.seswar.warrant.warrant.push;

import io.seswar.warrant.warrant.api.IssueWarrantCommand;
import io.seswar.warrant.warrant.store.OnExpiry;
import io.seswar.warrant.warrant.store.Warrant;
import io.seswar.warrant.warrant.store.WarrantMode;
import io.seswar.warrant.warrant.WarrantProtoMapper;
import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import io.grpc.stub.StreamObserver;
import io.seswar.warrant.warrant.WarrantIssuanceService;
import io.seswar.warrant.warrant.WarrantRevocationService;
import io.seswar.warrant.warrant.WarrantSealer;
import io.seswar.warrant.signing.SigningKeyProvider;
import io.seswar.warrant.signing.WarrantSigner;
import io.seswar.warrant.policy.ExecRule;
import io.seswar.warrant.policy.Policy;
import io.seswar.warrant.identity.Subject;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.seswar.warrant.node.Node;
import io.seswar.warrant.node.NodeRepository;
import io.seswar.warrant.proto.AgentProtos.ExtensionAck;
import io.seswar.warrant.proto.AgentProtos.ExtensionRequest;
import io.seswar.warrant.proto.AgentProtos.HeartbeatRequest;
import io.seswar.warrant.proto.AgentProtos.LookupRequest;
import io.seswar.warrant.proto.AgentProtos.LookupResponse;
import io.seswar.warrant.proto.AgentProtos.NodeHello;
import io.seswar.warrant.proto.AgentProtos.PushMessage;
import io.seswar.warrant.proto.AgentProtos.SubscribeRequest;
import io.seswar.warrant.proto.WarrantProtos;
import io.seswar.warrant.proto.WarrantPushServiceGrpc;
import io.seswar.warrant.policy.PolicyRepository;
import io.seswar.warrant.identity.SubjectRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.nio.file.Files;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

// A real in-process gRPC stream over real PostgreSQL. Issuing commits for real, so each test uses its own hosts.
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Transactional(propagation = Propagation.NOT_SUPPORTED)
@Testcontainers
@Import({WarrantPushGrpcService.class, WarrantPushService.class, NodeStreamRegistry.class,
        WarrantIssuanceService.class, WarrantRevocationService.class, WarrantSealer.class,
        WarrantProtoMapper.class, WarrantSigner.class, io.seswar.warrant.policy.PolicyLinter.class,
        io.seswar.warrant.warrant.WarrantExtensionService.class, io.seswar.warrant.approval.ApproverEligibility.class,
        WarrantPushGrpcServiceTest.Keys.class})
class WarrantPushGrpcServiceTest {

    @Container
    @ServiceConnection
    static PostgreSQLContainer postgres = new PostgreSQLContainer("postgres:18");

    @TestConfiguration
    static class Keys {
        @Bean
        Clock clock() {
            return Clock.systemUTC();
        }

        @Bean
        SigningKeyProvider signingKeyProvider() throws Exception {
            return new SigningKeyProvider(Files.createTempDirectory("sk").resolve("signing.key").toString(), "central");
        }
    }

    @Autowired WarrantPushGrpcService service;
    @Autowired WarrantIssuanceService issuance;
    @Autowired WarrantRevocationService revocation;
    @Autowired WarrantPushService push;
    @Autowired WarrantSigner signer;
    @Autowired SubjectRepository subjects;
    @Autowired PolicyRepository policies;
    @Autowired NodeRepository nodes;

    Server server;
    ManagedChannel channel;
    String host;
    Subject alice;
    Policy policy;

    @BeforeEach
    void start() throws Exception {
        String name = InProcessServerBuilder.generateName();
        server = InProcessServerBuilder.forName(name).addService(service).build().start();
        channel = InProcessChannelBuilder.forName(name).build();
        host = "node-" + UUID.randomUUID();
        alice = subjects.saveAndFlush(Subject.of("oidc|" + UUID.randomUUID(), "alice@example.com", "ec2-user",
                List.of("SHA256:alice-" + UUID.randomUUID())));
        policy = policies.saveAndFlush(Policy.of("ops", false, List.of(new ExecRule("/usr/bin/ls")), List.of(), List.of()));
    }

    @AfterEach
    void stop() throws Exception {
        channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
        server.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
    }

    Warrant issueFor(String... hosts) {
        return issuance.issue(new IssueWarrantCommand(alice.getId(), "ec2-user", "INC-1", List.of(hosts),
                policy.getId(), Duration.ofMinutes(30), WarrantMode.DRYRUN, OnExpiry.DEMOTE, Duration.ZERO));
    }

    // Opens a subscription as warrantd would and collects what arrives.
    BlockingQueue<PushMessage> subscribe(String hostname) {
        BlockingQueue<PushMessage> got = new LinkedBlockingQueue<>();
        WarrantPushServiceGrpc.newStub(channel).subscribe(
                SubscribeRequest.newBuilder().setNode(NodeHello.newBuilder().setHostname(hostname)).build(),
                new StreamObserver<>() {
                    public void onNext(PushMessage m) { got.add(m); }
                    public void onError(Throwable t) { }
                    public void onCompleted() { }
                });
        return got;
    }

    static PushMessage next(BlockingQueue<PushMessage> q) throws InterruptedException {
        PushMessage m = q.poll(5, TimeUnit.SECONDS);
        assertThat(m).as("push message").isNotNull();
        return m;
    }

    static WarrantProtos.Warrant warrantOf(PushMessage m) throws Exception {
        assertThat(m.hasWarrant()).as("warrant message").isTrue();
        return WarrantProtos.Warrant.parseFrom(m.getWarrant().getWarrant());
    }

    @Test
    void 구독하면_그_노드의_살아_있는_영장과_ResyncComplete가_온다() throws Exception {
        Warrant mine = issueFor(host);
        issueFor("other-" + host);
        Warrant revoked = issueFor(host);
        revocation.revoke(revoked.getId());

        BlockingQueue<PushMessage> q = subscribe(host);

        assertThat(warrantOf(next(q)).getWarrantId()).isEqualTo(mine.getWarrantId());
        PushMessage done = next(q);
        assertThat(done.hasResyncComplete()).isTrue();
        assertThat(done.getResyncComplete().getActiveCount()).isEqualTo(1);
    }

    // 노드는 받은 바이트 그대로 서명을 검증한다. 서버가 저장한 바이트가 그대로 가야 한다.
    @Test
    void 보내는_봉투는_저장된_바이트와_서명_그대로다() throws Exception {
        Warrant mine = issueFor(host);

        PushMessage m = next(subscribe(host));

        assertThat(m.getWarrant().getWarrant().toByteArray()).isEqualTo(mine.getSignedPayload());
        assertThat(m.getWarrant().getSignature().toByteArray()).isEqualTo(mine.getSignature());
        assertThat(m.getWarrant().getKeyId()).isEqualTo("central");
        assertThat(signer.verify(m.getWarrant().getWarrant().toByteArray(), m.getWarrant().getSignature().toByteArray())).isTrue();
    }

    @Test
    void 구독_중에_발급하면_바로_온다() throws Exception {
        BlockingQueue<PushMessage> q = subscribe(host);
        assertThat(next(q).hasResyncComplete()).isTrue();

        Warrant w = issueFor(host);
        push.push(w);

        assertThat(warrantOf(next(q)).getWarrantId()).isEqualTo(w.getWarrantId());
    }

    @Test
    void 구독_중에_취소하면_취소된_새_revision이_온다() throws Exception {
        Warrant w = issueFor(host);
        BlockingQueue<PushMessage> q = subscribe(host);
        next(q);
        next(q);

        push.push(revocation.revoke(w.getId()));

        WarrantProtos.Warrant p = warrantOf(next(q));
        assertThat(p.getRevoked()).isTrue();
        assertThat(p.getRevision()).isEqualTo(2);
    }

    @Test
    void 다른_노드_앞으로_발급한_영장은_오지_않는다() throws Exception {
        BlockingQueue<PushMessage> q = subscribe(host);
        next(q);

        push.push(issueFor("other-" + host));

        assertThat(q.poll(300, TimeUnit.MILLISECONDS)).isNull();
    }

    // ── Heartbeat ───────────────────────────────────────────────────────────────

    int heartbeat(String hostname, int active) {
        return WarrantPushServiceGrpc.newBlockingStub(channel).heartbeat(HeartbeatRequest.newBuilder()
                .setNode(NodeHello.newBuilder().setHostname(hostname)).setActiveWarrants(active).build())
                .getExpectedActiveWarrants();
    }

    @Test
    void 생존_신호에는_그_노드가_들고_있어야_할_활성_영장_수로_답한다() {
        issueFor(host);
        issueFor(host);
        revocation.revoke(issueFor(host).getId());
        issueFor("other-" + host);

        assertThat(heartbeat(host, 0)).isEqualTo(2);
    }

    @Test
    void 생존_신호는_노드의_마지막_소식_시각을_갱신한다() {
        Instant old = Instant.parse("2026-01-01T00:00:00Z");
        Node n = nodes.saveAndFlush(Node.builder().clientCertFingerprint("dev:" + host).hostname(host)
                .attachedHooks(Set.of()).lastSeenAt(old).build());

        heartbeat(host, 0);

        assertThat(nodes.findById(n.getId()).orElseThrow().getLastSeenAt()).isAfter(old);
    }

    @Test
    void 처음_보는_노드의_생존_신호는_노드를_만들지_않고_답만_한다() {
        assertThat(heartbeat(host, 0)).isZero();
        assertThat(nodes.findByClientCertFingerprint("dev:" + host)).isEmpty();
    }

    @Test
    void 호스트_이름이_빈_생존_신호는_거부한다() {
        assertThatThrownBy(() -> heartbeat("", 0))
                .isInstanceOfSatisfying(StatusRuntimeException.class,
                        e -> assertThat(e.getStatus().getCode()).isEqualTo(Status.Code.INVALID_ARGUMENT));
    }

    // ── LookupActiveWarrant ─────────────────────────────────────────────────────

    LookupResponse lookup(String hostname, String account, String fingerprint) {
        return WarrantPushServiceGrpc.newBlockingStub(channel).lookupActiveWarrant(LookupRequest.newBuilder()
                .setHostname(hostname).setLoginAccount(account).setSshKeyFingerprint(fingerprint).build());
    }

    @Test
    void 조회는_노드_계정_키_지문이_셋_다_맞는_활성_영장만_돌려준다() throws Exception {
        Warrant mine = issueFor(host);
        issueFor("other-" + host);
        String fp = alice.getSshKeyFingerprints().iterator().next();

        LookupResponse r = lookup(host, "ec2-user", fp);

        assertThat(r.getWarrantsList()).hasSize(1);
        assertThat(r.getWarrants(0).getWarrant().toByteArray()).isEqualTo(mine.getSignedPayload());
        assertThat(r.getWarrants(0).getSignature().toByteArray()).isEqualTo(mine.getSignature());
    }

    @Test
    void 계정이나_지문이_다르거나_비었으면_빈_응답이다() {
        issueFor(host);
        String fp = alice.getSshKeyFingerprints().iterator().next();

        assertThat(lookup(host, "root", fp).getWarrantsList()).isEmpty();
        assertThat(lookup(host, "ec2-user", "SHA256:someone-else").getWarrantsList()).isEmpty();
        assertThat(lookup(host, "ec2-user", "").getWarrantsList()).isEmpty();
        assertThat(lookup("other-" + host, "ec2-user", fp).getWarrantsList()).isEmpty();
    }

    @Test
    void 취소된_영장은_조회되지_않는다() {
        revocation.revoke(issueFor(host).getId());
        String fp = alice.getSshKeyFingerprints().iterator().next();

        assertThat(lookup(host, "ec2-user", fp).getWarrantsList()).isEmpty();
    }

    // ── RequestExtension ────────────────────────────────────────────────────────

    ExtensionAck requestExtension(long warrantId) {
        return WarrantPushServiceGrpc.newBlockingStub(channel).requestExtension(ExtensionRequest.newBuilder()
                .setWarrantId(warrantId).setDetectedWorkload("deploy.sh (pid 4821)").build());
    }

    // 이 테스트의 정책은 쓰기 규칙이 없다 — 자동 승인 범위라 즉답이 AUTO_APPROVED 이고 새 revision 이 바로 push 된다.
    @Test
    void 자동_승인된_연장은_새_revision으로_바로_내려간다() throws Exception {
        Warrant w = issueFor(host);
        BlockingQueue<PushMessage> q = subscribe(host);
        next(q);
        next(q);

        ExtensionAck ack = requestExtension(w.getWarrantId());

        assertThat(ack.getOutcome()).isEqualTo(ExtensionAck.Outcome.OUTCOME_AUTO_APPROVED);
        WarrantProtos.Warrant p = warrantOf(next(q));
        assertThat(p.getWarrantId()).isEqualTo(w.getWarrantId());
        assertThat(p.getRevision()).isEqualTo(2);
        assertThat(p.getRevoked()).isFalse();
    }

    @Test
    void 모르는_영장의_연장_요청은_거부로_답한다() {
        assertThat(requestExtension(Long.MAX_VALUE).getOutcome()).isEqualTo(ExtensionAck.Outcome.OUTCOME_REJECTED);
    }
}
