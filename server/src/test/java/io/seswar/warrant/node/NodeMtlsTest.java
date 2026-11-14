package io.seswar.warrant.node;

import io.grpc.ChannelCredentials;
import io.grpc.Grpc;
import io.grpc.ManagedChannel;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.TlsChannelCredentials;
import io.grpc.stub.StreamObserver;
import io.seswar.warrant.proto.AgentProtos.AuditAck;
import io.seswar.warrant.proto.AgentProtos.AuditBatch;
import io.seswar.warrant.proto.AgentProtos.NodeHello;
import io.seswar.warrant.proto.AgentProtos.PushMessage;
import io.seswar.warrant.proto.AgentProtos.SubscribeRequest;
import io.seswar.warrant.proto.AuditIngestServiceGrpc;
import io.seswar.warrant.proto.WarrantPushServiceGrpc;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.grpc.test.autoconfigure.LocalGrpcServerPort;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.core.io.ClassPathResource;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.io.File;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

// 노드 ↔ 중앙 gRPC 의 mTLS. 인증서는 src/test/resources/mtls (deploy/pki/pki.sh 로 만든 시험 전용).
@SpringBootTest(properties = "spring.grpc.server.port=0")
@ActiveProfiles({"dev", "mtls"})
@Testcontainers
class NodeMtlsTest {

    @Container
    @ServiceConnection
    static PostgreSQLContainer postgres = new PostgreSQLContainer("postgres:18");

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry r) throws Exception {
        String path = Files.createTempDirectory("sk").resolve("signing.key").toString();
        r.add("warrant.signing.key-path", () -> path);
        r.add("spring.ssl.bundle.pem.node-grpc.keystore.certificate", () -> "classpath:mtls/server.pem");
        r.add("spring.ssl.bundle.pem.node-grpc.keystore.private-key", () -> "classpath:mtls/server.key");
        r.add("spring.ssl.bundle.pem.node-grpc.truststore.certificate", () -> "classpath:mtls/ca.pem");
    }

    @LocalGrpcServerPort int port;
    @Autowired NodeRepository nodes;

    final List<ManagedChannel> channels = new ArrayList<>();

    @AfterEach
    void close() {
        channels.forEach(ManagedChannel::shutdownNow);
    }

    static File res(String name) throws Exception {
        return new ClassPathResource("mtls/" + name).getFile();
    }

    // A node holding `cert`/`key` (null = no client certificate), trusting the test CA.
    ManagedChannel channel(String cert, String key) throws Exception {
        var b = TlsChannelCredentials.newBuilder().trustManager(res("ca.pem"));
        if (cert != null) {
            b.keyManager(res(cert), res(key));
        }
        ChannelCredentials creds = b.build();
        ManagedChannel ch = Grpc.newChannelBuilderForAddress("localhost", port, creds).build();
        channels.add(ch);
        return ch;
    }

    static NodeHello hello(String host) {
        return NodeHello.newBuilder().setHostname(host).setKernelVersion("6.8").setAgentVersion("test").build();
    }

    // Sends one NodeHello batch and returns the first ack, or throws the stream's error.
    static AuditAck firstAck(ManagedChannel ch, String host) throws Exception {
        CompletableFuture<AuditAck> got = new CompletableFuture<>();
        StreamObserver<AuditBatch> up = AuditIngestServiceGrpc.newStub(ch).stream(new StreamObserver<>() {
            @Override public void onNext(AuditAck a) { got.complete(a); }
            @Override public void onError(Throwable t) { got.completeExceptionally(t); }
            @Override public void onCompleted() { }
        });
        up.onNext(AuditBatch.newBuilder().setSeqEpoch(7).setNode(hello(host)).build());
        try {
            return got.get(10, TimeUnit.SECONDS);
        } catch (java.util.concurrent.ExecutionException e) {
            throw (Exception) e.getCause();
        } finally {
            up.onCompleted();
        }
    }

    static String fingerprint(String pem) throws Exception {
        X509Certificate c;
        try (var in = new java.io.FileInputStream(res(pem))) {
            c = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        }
        return "sha256:" + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(c.getEncoded()));
    }

    static Status.Code code(Throwable t) {
        return Status.fromThrowable(t).getCode();
    }

    // 신원은 인증서다. 노드가 스스로 말하는 호스트 이름이 아니다.
    @Test
    void 인증서로_붙은_노드는_인증서_지문을_신원으로_등록된다() throws Exception {
        firstAck(channel("node-a.pem", "node-a.key"), "node-a");

        var node = nodes.findByClientCertFingerprint(fingerprint("node-a.pem"));
        assertThat(node).isPresent();
        assertThat(node.get().getHostname()).isEqualTo("node-a");
    }

    // 남의 노드 이름을 대면 그 노드의 감사 기록을 오염시키거나 영장을 엿볼 수 있다.
    @Test
    void 인증서와_다른_호스트_이름을_대면_감사_스트림을_거부한다() {
        assertThatThrownBy(() -> firstAck(channel("node-a.pem", "node-a.key"), "node-b"))
                .satisfies(t -> assertThat(code(t)).isEqualTo(Status.Code.PERMISSION_DENIED));
        assertThat(nodes.findByHostname("node-b")).isEmpty();
    }

    @Test
    void 인증서와_다른_호스트_이름으로는_영장을_구독할_수_없다() throws Exception {
        var it = WarrantPushServiceGrpc.newBlockingStub(channel("node-a.pem", "node-a.key"))
                .withDeadlineAfter(10, TimeUnit.SECONDS)
                .subscribe(SubscribeRequest.newBuilder().setNode(hello("node-b")).build());
        assertThatThrownBy(it::next).isInstanceOfSatisfying(StatusRuntimeException.class,
                e -> assertThat(e.getStatus().getCode()).isEqualTo(Status.Code.PERMISSION_DENIED));
    }

    @Test
    void 자기_호스트_이름으로는_영장을_구독한다() throws Exception {
        var it = WarrantPushServiceGrpc.newBlockingStub(channel("node-a.pem", "node-a.key"))
                .withDeadlineAfter(10, TimeUnit.SECONDS)
                .subscribe(SubscribeRequest.newBuilder().setNode(hello("node-a")).build());
        PushMessage first = it.next();
        assertThat(first.hasResyncComplete()).isTrue();
    }

    @Test
    void 클라이언트_인증서가_없으면_붙지_못한다() {
        assertThatThrownBy(() -> firstAck(channel(null, null), "node-a"))
                .satisfies(t -> assertThat(code(t)).isEqualTo(Status.Code.UNAVAILABLE));
    }

    @Test
    void 다른_CA가_발급한_인증서로는_붙지_못한다() {
        assertThatThrownBy(() -> firstAck(channel("rogue-node-a.pem", "rogue-node-a.key"), "node-a"))
                .satisfies(t -> assertThat(code(t)).isEqualTo(Status.Code.UNAVAILABLE));
    }
}
