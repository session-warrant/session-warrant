package io.seswar.warrant.warrant.push;

import io.seswar.warrant.warrant.WarrantProtoMapper;
import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import io.grpc.stub.StreamObserver;
import io.seswar.warrant.warrant.IssueWarrantCommand;
import io.seswar.warrant.warrant.WarrantIssuanceService;
import io.seswar.warrant.warrant.push.WarrantPushService;
import io.seswar.warrant.warrant.WarrantRevocationService;
import io.seswar.warrant.warrant.WarrantSealer;
import io.seswar.warrant.signing.SigningKeyProvider;
import io.seswar.warrant.signing.WarrantSigner;
import io.seswar.warrant.policy.ExecRule;
import io.seswar.warrant.policy.Policy;
import io.seswar.warrant.identity.Subject;
import io.seswar.warrant.warrant.OnExpiry;
import io.seswar.warrant.warrant.Warrant;
import io.seswar.warrant.warrant.WarrantMode;
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
import java.util.List;
import java.util.UUID;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

// A real in-process gRPC stream over real PostgreSQL. Issuing commits for real, so each test uses its own hosts.
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Transactional(propagation = Propagation.NOT_SUPPORTED)
@Testcontainers
@Import({WarrantPushGrpcService.class, WarrantPushService.class, NodeStreamRegistry.class,
        WarrantIssuanceService.class, WarrantRevocationService.class, WarrantSealer.class,
        WarrantProtoMapper.class, WarrantSigner.class, WarrantPushGrpcServiceTest.Keys.class})
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
}
