package io.seswar.warrant.audit;

import com.jayway.jsonpath.JsonPath;
import io.seswar.warrant.node.NodeRegistry;
import io.seswar.warrant.proto.AgentProtos.AuditBatch;
import io.seswar.warrant.proto.AuditProtos;
import io.seswar.warrant.proto.WarrantProtos;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.nio.file.Files;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

// 대시보드가 새로고침 없이 따라가는 길: 수신 순번으로 이어 받는 차분 조회.
@SpringBootTest(properties = "spring.grpc.server.port=0")
@AutoConfigureMockMvc
@ActiveProfiles("dev")
@Testcontainers
class AuditFeedApiTest {

    @Container
    @ServiceConnection
    static PostgreSQLContainer postgres = new PostgreSQLContainer("postgres:18");

    static final String ALICE = "alice@example.com", PW = "pw";

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry r) throws Exception {
        String path = Files.createTempDirectory("sk").resolve("signing.key").toString();
        r.add("warrant.signing.key-path", () -> path);
        r.add("warrant.dev.accounts[0].email", () -> ALICE);
        r.add("warrant.dev.accounts[0].password", () -> "{noop}" + PW);
    }

    @Autowired MockMvc mvc;
    @Autowired AuditIngestService ingest;
    @Autowired NodeRegistry nodes;

    UUID node;
    String host;
    long nextSeq = 1;

    @BeforeEach
    void node() {
        host = "node-" + UUID.randomUUID();
        node = nodes.register("dev:" + host, new NodeRegistry.Report(host, "6.8", true, "test", Set.of(), null, 9)).nodeId();
    }

    // One kernel write verdict that happened at `at`, stored now.
    void arrive(Instant at, long ino) {
        long seq = nextSeq++;
        var e = AuditProtos.AuditEvent.newBuilder()
                .setNodeSeq(seq).setWallTsUnixNs(at.getEpochSecond() * 1_000_000_000L + at.getNano()).setWarrantId(8)
                .setHook(AuditProtos.Hook.HOOK_FILE_OPEN)
                .setVerdict(AuditProtos.Verdict.VERDICT_WOULD_DENY)
                .setMode(WarrantProtos.Mode.MODE_DRYRUN)
                .setOrigin(AuditProtos.Origin.ORIGIN_LSM)
                .setTagSource(AuditProtos.TagSource.TAG_CGROUP)
                .setFileWrite(AuditProtos.FileWriteEvent.newBuilder().setFile(AuditProtos.FileRef.newBuilder().setDev(2049).setIno(ino)))
                .build();
        ingest.ingest(node, AuditProtoMapper.toBatch(node,
                AuditBatch.newBuilder().setSeqEpoch(9).setLastNodeSeq(seq).addEvents(e).build()));
    }

    MvcResult events(String query) throws Exception {
        return mvc.perform(get("/api/audit/events" + query).with(httpBasic(ALICE, PW)))
                .andExpect(status().isOk())
                .andReturn();
    }

    static long cursor(MvcResult r) {
        return Long.parseLong(r.getResponse().getHeader("X-Audit-Cursor"));
    }

    // Inodes of the returned rows, in response order.
    static List<Integer> inodes(MvcResult r) throws Exception {
        return JsonPath.read(r.getResponse().getContentAsString(), "$[*].inode");
    }

    // 서버가 죽어 있던 동안 쌓였다가 재전송된 기록은 발생 시각이 과거다. 발생 시각으로 이어 받으면 영영 빠진다.
    @Test
    void 늦게_도착한_과거_기록도_차분_조회에_잡힌다() throws Exception {
        arrive(Instant.now(), 1);
        long first = cursor(events(""));

        arrive(Instant.now().minus(Duration.ofHours(1)), 2);
        MvcResult diff = events("?after=" + first);
        assertThat(inodes(diff)).containsExactly(2);
        long second = cursor(diff);
        assertThat(second).isGreaterThan(first);

        MvcResult none = events("?after=" + second);
        assertThat(inodes(none)).isEmpty();
        assertThat(cursor(none)).isEqualTo(second);
    }

    @Test
    void 한_번에_다_못_주면_받은_데까지를_다음_시작점으로_준다() throws Exception {
        long start = cursor(events(""));
        arrive(Instant.now(), 11);
        arrive(Instant.now(), 12);
        arrive(Instant.now(), 13);

        MvcResult page = events("?after=" + start + "&limit=2");
        assertThat(inodes(page)).containsExactly(11, 12);
        assertThat(inodes(events("?after=" + cursor(page)))).containsExactly(13);
    }
}
