package io.seswar.warrant.grpc;

import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.Status;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import io.grpc.stub.StreamObserver;
import io.seswar.warrant.application.AuditIngestService;
import io.seswar.warrant.application.NodeRegistry;
import io.seswar.warrant.config.ClockConfig;
import io.seswar.warrant.proto.AgentProtos.AuditAck;
import io.seswar.warrant.proto.AgentProtos.AuditBatch;
import io.seswar.warrant.proto.AgentProtos.NodeHello;
import io.seswar.warrant.proto.AuditIngestServiceGrpc;
import io.seswar.warrant.proto.AuditProtos;
import io.seswar.warrant.proto.AuditProtos.Hook;
import io.seswar.warrant.proto.AuditProtos.Origin;
import io.seswar.warrant.proto.AuditProtos.TagSource;
import io.seswar.warrant.proto.AuditProtos.UnwarrantedSessionEvent;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

// A real gRPC stream (in-process) over real PostgreSQL. Each batch commits for real, so there is
// no per-test rollback; audit tables are append-only, so each test uses its own node instead.
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Transactional(propagation = Propagation.NOT_SUPPORTED)
@Testcontainers
@Import({AuditIngestGrpcService.class, AuditIngestService.class, NodeRegistry.class, ClockConfig.class})
class AuditIngestGrpcServiceTest {

    @Container
    @ServiceConnection
    static PostgreSQLContainer postgres = new PostgreSQLContainer("postgres:18");

    static final Instant T = Instant.parse("2026-10-20T00:00:00Z");
    static final long T_NS = T.getEpochSecond() * 1_000_000_000L;

    @Autowired AuditIngestGrpcService service;
    @Autowired JdbcTemplate jdbc;

    Server server;
    ManagedChannel channel;
    String host;

    @BeforeEach
    void start() throws Exception {
        String name = InProcessServerBuilder.generateName();
        server = InProcessServerBuilder.forName(name).addService(service).build().start();
        channel = InProcessChannelBuilder.forName(name).build();
        host = "node-" + UUID.randomUUID();
    }

    @AfterEach
    void stop() throws Exception {
        channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
        server.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
    }

    /** warrantd 쪽 끝. 서버가 보낸 ack 와 스트림이 끝난 방식을 모은다. */
    static final class Agent implements StreamObserver<AuditAck> {
        final BlockingQueue<AuditAck> acks = new LinkedBlockingQueue<>();
        final CompletableFuture<Status> closed = new CompletableFuture<>();
        StreamObserver<AuditBatch> out;

        @Override public void onNext(AuditAck a) { acks.add(a); }
        @Override public void onError(Throwable t) { closed.complete(Status.fromThrowable(t)); }
        @Override public void onCompleted() { closed.complete(Status.OK); }

        // Fails as soon as the stream is closed with no ack pending, showing why it closed.
        AuditAck nextAck() throws Exception {
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            while (System.nanoTime() < deadline) {
                AuditAck a = acks.poll(50, TimeUnit.MILLISECONDS);
                if (a != null) {
                    return a;
                }
                if (closed.isDone() && acks.isEmpty()) {
                    throw new AssertionError("ack 를 기다리는데 스트림이 닫혔다: " + closed.get());
                }
            }
            throw new AssertionError("ack 가 5초 안에 오지 않았다");
        }

        Status closedWith() throws Exception {
            return closed.get(5, TimeUnit.SECONDS);
        }
    }

    private Agent connect() {
        Agent agent = new Agent();
        agent.out = AuditIngestServiceGrpc.newStub(channel).stream(agent);
        return agent;
    }

    private NodeHello hello(String agentVersion) {
        return NodeHello.newBuilder()
                .setHostname(host).setKernelVersion("7.0.0-15-generic").setBpfLsmEnabled(true)
                .setAgentVersion(agentVersion).addAttachedHooks(Hook.HOOK_BPRM_CHECK_SECURITY)
                .setBootedAtUnixNs(T_NS - 3_600_000_000_000L)
                .build();
    }

    private static AuditProtos.AuditEvent unwarranted(long seq) {
        return AuditProtos.AuditEvent.newBuilder()
                .setNodeSeq(seq).setWallTsUnixNs(T_NS + seq)
                .setHook(Hook.HOOK_AGENT).setVerdict(AuditProtos.Verdict.VERDICT_ALLOW)
                .setOrigin(Origin.ORIGIN_AGENT).setTagSource(TagSource.TAG_NONE)
                .setUnwarrantedSession(UnwarrantedSessionEvent.newBuilder()
                        .setLoginAccount("ec2-user").setSourceAddress("10.0.0.5").setCgroupId(7594)
                        .setReason(UnwarrantedSessionEvent.Reason.REASON_NO_KEY))
                .build();
    }

    // Events seq from..to, with last_node_seq = to. Pass hello = null for a batch without NodeHello.
    private static AuditBatch batch(NodeHello hello, long epoch, long from, long to) {
        AuditBatch.Builder b = AuditBatch.newBuilder().setSeqEpoch(epoch).setLastNodeSeq(to);
        if (hello != null) {
            b.setNode(hello);
        }
        for (long s = from; s <= to; s++) {
            b.addEvents(unwarranted(s));
        }
        return b.build();
    }

    private UUID nodeId() {
        return jdbc.queryForObject("select id from node where client_cert_fingerprint = ?", UUID.class, "dev:" + host);
    }

    private long rows(String table) {
        return jdbc.queryForObject("select count(*) from " + table + " where node_id = ?", Long.class, nodeId());
    }

    private long nodesNamedHost() {
        return jdbc.queryForObject("select count(*) from node where hostname = ?", Long.class, host);
    }

    @Test
    void 무영장_접속_기록을_보내면_저장되고_확인을_받는다() throws Exception {
        Agent agent = connect();
        agent.out.onNext(batch(hello("warrantd 0.1.0"), 7, 1, 3));

        AuditAck ack = agent.nextAck();
        assertThat(ack.getSeqEpoch()).isEqualTo(7);
        assertThat(ack.getAckedThroughNodeSeq()).isEqualTo(3);  // 3번까지 지워도 된다
        assertThat(rows("audit_event")).isEqualTo(3);
        assertThat(rows("unwarranted_session")).isEqualTo(3);

        agent.out.onCompleted();
        assertThat(agent.closedWith().isOk()).isTrue();
    }

    @Test
    void 확인을_못_받아_다시_보내도_한번만_저장되고_확인은_다시_온다() throws Exception {
        Agent first = connect();
        first.out.onNext(batch(hello("warrantd 0.1.0"), 7, 1, 3));
        first.nextAck();
        first.out.onCompleted();
        first.closedWith();

        // 다시 연결해서 같은 묶음을 보낸다 — ack 가 도중에 사라졌을 때 warrantd 가 하는 일
        Agent again = connect();
        again.out.onNext(batch(hello("warrantd 0.1.0"), 7, 1, 3));

        assertThat(again.nextAck().getAckedThroughNodeSeq()).isEqualTo(3);
        assertThat(rows("audit_event")).isEqualTo(3);
        assertThat(rows("unwarranted_session")).isEqualTo(3);
        assertThat(nodesNamedHost()).isEqualTo(1);
        again.out.onCompleted();
    }

    @Test
    void 첫_묶음에_노드_정보가_없으면_연결을_끊는다() throws Exception {
        Agent agent = connect();
        agent.out.onNext(batch(null, 7, 1, 3));

        assertThat(agent.closedWith().getCode()).isEqualTo(Status.Code.INVALID_ARGUMENT);
        assertThat(agent.acks).isEmpty();
        assertThat(nodesNamedHost()).isZero();  // 누구 기록인지 모르니 노드도 만들지 않는다
    }

    @Test
    void 잘못된_기록이_섞인_묶음은_확인하지_않고_연결을_끊는다() throws Exception {
        Agent agent = connect();
        agent.out.onNext(batch(hello("warrantd 0.1.0"), 7, 1, 2));
        agent.nextAck();

        AuditBatch broken = batch(null, 7, 3, 4).toBuilder()
                .setEvents(1, unwarranted(4).toBuilder().setWallTsUnixNs(0))  // 시각이 비어 있다
                .build();
        agent.out.onNext(broken);

        assertThat(agent.closedWith().getCode()).isEqualTo(Status.Code.INVALID_ARGUMENT);
        assertThat(agent.acks).isEmpty();          // 앞 묶음의 ack 하나만 왔다 → warrantd 는 3번부터 다시 보낸다
        assertThat(rows("audit_event")).isEqualTo(2);  // 깨진 묶음은 한 건도 안 들어간다
    }

    @Test
    void 연결_도중_노드_정보가_다시_오면_같은_노드를_갱신한다() throws Exception {
        Agent agent = connect();
        agent.out.onNext(batch(hello("warrantd 0.1.0"), 7, 1, 1));
        agent.nextAck();
        UUID before = nodeId();

        agent.out.onNext(batch(hello("warrantd 0.2.0"), 7, 2, 2));
        agent.nextAck();

        assertThat(nodeId()).isEqualTo(before);
        assertThat(nodesNamedHost()).isEqualTo(1);
        assertThat(jdbc.queryForObject("select agent_version from node where id = ?", String.class, before))
                .isEqualTo("warrantd 0.2.0");
        agent.out.onCompleted();
    }

    @Test
    void 노드의_로컬저장소가_초기화된_뒤_다시_접속하면_새_번호부터_이어서_받는다() throws Exception {
        Agent before = connect();
        before.out.onNext(batch(hello("warrantd 0.1.0"), 7, 1, 3));
        before.nextAck();
        before.out.onCompleted();
        before.closedWith();

        // 초기화 뒤에는 번호가 1 부터 다시 시작하고 epoch 가 바뀐다. 옛 1~3 과 겹친다고 버리면 안 된다
        Agent after = connect();
        after.out.onNext(batch(hello("warrantd 0.1.0"), 8, 1, 2));
        AuditAck ack = after.nextAck();

        assertThat(ack.getSeqEpoch()).isEqualTo(8);
        assertThat(ack.getAckedThroughNodeSeq()).isEqualTo(2);
        assertThat(rows("audit_event")).isEqualTo(5);
        assertThat(jdbc.queryForObject("select current_seq_epoch from node where id = ?", Long.class, nodeId()))
                .isEqualTo(8L);
        after.out.onCompleted();
    }

    @Test
    void 연결_도중_노드_정보_없이_번호_세대가_바뀌면_연결을_끊는다() throws Exception {
        Agent agent = connect();
        agent.out.onNext(batch(hello("warrantd 0.1.0"), 7, 1, 3));
        agent.nextAck();

        // 세대는 로컬저장소를 새로 만들 때만 바뀌고, 그러려면 warrantd 가 다시 떠서 새로 접속해야 한다
        agent.out.onNext(batch(null, 8, 1, 2));

        assertThat(agent.closedWith().getCode()).isEqualTo(Status.Code.INVALID_ARGUMENT);
        assertThat(agent.acks).isEmpty();
        assertThat(rows("audit_event")).isEqualTo(3);  // 새 세대 기록은 한 건도 안 들어간다
        assertThat(jdbc.queryForObject("select current_seq_epoch from node where id = ?", Long.class, nodeId()))
                .isEqualTo(7L);
    }

    @Test
    void 연결_도중_노드_정보와_함께_번호_세대가_바뀌어도_연결을_끊는다() throws Exception {
        Agent agent = connect();
        agent.out.onNext(batch(hello("warrantd 0.1.0"), 7, 1, 3));
        agent.nextAck();

        // 노드 정보가 붙어 있다고 달라지지 않는다. 세대는 한 연결 안에서 바뀔 수 없다
        agent.out.onNext(batch(hello("warrantd 0.2.0"), 8, 1, 2));

        assertThat(agent.closedWith().getCode()).isEqualTo(Status.Code.INVALID_ARGUMENT);
        assertThat(agent.acks).isEmpty();
        assertThat(rows("audit_event")).isEqualTo(3);
        Map<String, Object> node = jdbc.queryForMap("select * from node where id = ?", nodeId());
        assertThat(node.get("current_seq_epoch")).isEqualTo(7L);         // 노드 기록도 그대로
        assertThat(node.get("agent_version")).isEqualTo("warrantd 0.1.0");
    }

    @Test
    void 번호_세대가_비어_있으면_연결을_끊는다() throws Exception {
        Agent agent = connect();
        // 0 은 warrantd 가 세대를 안 채웠다는 뜻이다. 받아 주면 초기화 뒤 새 기록이 옛 기록으로 보여 버려진다
        agent.out.onNext(batch(hello("warrantd 0.1.0"), 0, 1, 3));

        assertThat(agent.closedWith().getCode()).isEqualTo(Status.Code.INVALID_ARGUMENT);
        assertThat(agent.acks).isEmpty();
        assertThat(nodesNamedHost()).isZero();
    }
}
