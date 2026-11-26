package io.seswar.warrant.audit;

import com.jayway.jsonpath.JsonPath;
import io.seswar.warrant.node.NodeRegistry;
import io.seswar.warrant.proto.AgentProtos.AuditBatch;
import io.seswar.warrant.proto.AuditProtos.WriteAggregate;
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
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

// 허용된 쓰기 집계 — gRPC 배치로 들어온 것이 GET /api/audit/writes 로 나온다.
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = "spring.grpc.server.port=0")
@AutoConfigureMockMvc
@ActiveProfiles("dev")
@Testcontainers
class WriteAggregateApiTest {

    @Container
    @ServiceConnection
    static PostgreSQLContainer postgres = new PostgreSQLContainer("postgres:18");

    static final String ALICE = "alice@example.com", PW = "pw";
    static final long MINUTE_NS = 60_000_000_000L;

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

    @BeforeEach
    void node() {
        host = "node-" + UUID.randomUUID();
        node = nodes.register("dev:" + host, new NodeRegistry.Report(host, "6.8", true, "test", Set.of(), null, 9)).nodeId();
    }

    void arrive(long warrantId, Instant bucket, long count) {
        long ns = bucket.getEpochSecond() * 1_000_000_000L + bucket.getNano();
        ingest.ingest(node, AuditProtoMapper.toBatch(node, AuditBatch.newBuilder().setSeqEpoch(9)
                .addWriteAggregates(WriteAggregate.newBuilder()
                        .setWarrantId(warrantId).setBucketStartUnixNs(ns).setBucketNs(MINUTE_NS).setAllowedCount(count))
                .build()));
    }

    MvcResult writes(String query) throws Exception {
        return mvc.perform(get("/api/audit/writes" + query).with(httpBasic(ALICE, PW)))
                .andExpect(status().isOk()).andReturn();
    }

    static <T> List<T> read(MvcResult r, String path) throws Exception {
        return JsonPath.read(r.getResponse().getContentAsString(), path);
    }

    @Test
    void 영장_막대별_건수가_최신_막대부터_온다() throws Exception {
        Instant now = Instant.now().truncatedTo(ChronoUnit.MINUTES);
        arrive(12, now.minusSeconds(120), 5);
        arrive(12, now.minusSeconds(60), 8);

        MvcResult r = writes("?node=" + host);

        assertThat(read(r, "$[*].allowedCount")).containsExactly(8, 5);
        assertThat(read(r, "$[*].node")).containsOnly(host);
        assertThat(read(r, "$[*].bucketNs")).containsOnly(MINUTE_NS);
    }

    @Test
    void 영장_번호로_거를_수_있다() throws Exception {
        Instant now = Instant.now().truncatedTo(ChronoUnit.MINUTES);
        arrive(12, now, 5);
        arrive(13, now, 7);

        assertThat(read(writes("?node=" + host + "&warrant=13"), "$[*].warrantId")).containsExactly(13);
    }

    @Test
    void 구간_밖의_막대는_빠진다() throws Exception {
        Instant now = Instant.now().truncatedTo(ChronoUnit.MINUTES);
        arrive(12, now.minus(3, ChronoUnit.DAYS), 1);
        arrive(12, now, 2);

        assertThat(read(writes("?node=" + host), "$[*].allowedCount")).containsExactly(2);  // 기본 최근 24시간
    }
}
