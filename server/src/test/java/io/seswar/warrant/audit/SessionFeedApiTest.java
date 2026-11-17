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
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

// 「조직 전체 SSH 접속 현황」— 영장 세션과 무영장 세션을 한 줄기로 본다 (ssh_session 뷰).
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = "spring.grpc.server.port=0")
@AutoConfigureMockMvc
@ActiveProfiles("dev")
@Testcontainers
class SessionFeedApiTest {

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

    void warranted(Instant at, String account, long warrantId) {
        arrive(at, b -> b.setWarrantId(warrantId)
                .setMode(WarrantProtos.Mode.MODE_OBSERVE)
                .setTagSource(AuditProtos.TagSource.TAG_CGROUP)
                .setWarrantedSession(AuditProtos.WarrantedSessionEvent.newBuilder()
                        .setLoginAccount(account).setSourceAddress("10.0.0.9")
                        .setCgroupId(nextSeq * 1000).setSessionId("7")
                        .setSshKeyFingerprint("SHA256:abc")));
    }

    void unwarranted(Instant at, String account, AuditProtos.UnwarrantedSessionEvent.Reason why) {
        arrive(at, b -> b.setTagSource(AuditProtos.TagSource.TAG_NONE)
                .setUnwarrantedSession(AuditProtos.UnwarrantedSessionEvent.newBuilder()
                        .setLoginAccount(account).setSourceAddress("203.0.113.7")
                        .setCgroupId(nextSeq * 1000).setSessionId("7").setReason(why)
                        .setSshKeyFingerprint("SHA256:zzz")));
    }

    void arrive(Instant at, java.util.function.UnaryOperator<AuditProtos.AuditEvent.Builder> fill) {
        long seq = nextSeq++;
        var b = AuditProtos.AuditEvent.newBuilder()
                .setNodeSeq(seq)
                .setWallTsUnixNs(at.getEpochSecond() * 1_000_000_000L + at.getNano())
                .setHook(AuditProtos.Hook.HOOK_AGENT)
                .setVerdict(AuditProtos.Verdict.VERDICT_ALLOW)
                .setOrigin(AuditProtos.Origin.ORIGIN_AGENT);
        ingest.ingest(node, AuditProtoMapper.toBatch(node,
                AuditBatch.newBuilder().setSeqEpoch(9).setLastNodeSeq(seq).addEvents(fill.apply(b)).build()));
    }

    MvcResult sessions(String query) throws Exception {
        return mvc.perform(get("/api/audit/sessions" + query).with(httpBasic(ALICE, PW)))
                .andExpect(status().isOk()).andReturn();
    }

    static <T> List<T> read(MvcResult r, String path) throws Exception {
        return JsonPath.read(r.getResponse().getContentAsString(), path);
    }

    // $[0].reason 처럼 값 하나를 읽을 때. read() 로 받으면 List 로 캐스팅되어 터진다.
    static Object one(MvcResult r, String path) throws Exception {
        return JsonPath.read(r.getResponse().getContentAsString(), path);
    }

    @Test
    void 영장_세션과_무영장_세션이_한_목록에_온다() throws Exception {
        Instant now = Instant.now();
        warranted(now.minusSeconds(60), "ec2-user", 12);
        unwarranted(now.minusSeconds(30), "root", AuditProtos.UnwarrantedSessionEvent.Reason.REASON_NO_WARRANT);

        MvcResult r = sessions("?node=" + host);

        assertThat(read(r, "$[*].loginAccount")).containsExactly("root", "ec2-user");  // 최신 순
        assertThat(read(r, "$[*].warranted")).containsExactly(false, true);
    }

    @Test
    void 영장_세션은_영장_번호와_모드를_무영장_세션은_사유를_준다() throws Exception {
        Instant now = Instant.now();
        warranted(now.minusSeconds(60), "ec2-user", 12);
        unwarranted(now.minusSeconds(30), "root", AuditProtos.UnwarrantedSessionEvent.Reason.REASON_KEY_MISMATCH);

        MvcResult r = sessions("?node=" + host);

        assertThat(one(r, "$[0].reason")).isEqualTo("KEY_MISMATCH");
        assertThat(one(r, "$[0].warrantId")).isEqualTo(0);
        assertThat(one(r, "$[1].warrantId")).isEqualTo(12);
        assertThat(one(r, "$[1].mode")).isEqualTo("OBSERVE");   // 저장은 proto 이름이 아니라 WarrantMode 다
    }

    @Test
    void 구간_밖의_접속은_빠진다() throws Exception {
        Instant now = Instant.now();
        warranted(now.minus(3, ChronoUnit.DAYS), "old", 1);
        warranted(now.minusSeconds(10), "fresh", 2);

        MvcResult r = sessions("?node=" + host + "&since=" + now.minus(1, ChronoUnit.DAYS));

        assertThat(read(r, "$[*].loginAccount")).containsExactly("fresh");
    }

    @Test
    void 다른_노드의_접속은_안_섞인다() throws Exception {
        Instant now = Instant.now();
        warranted(now.minusSeconds(10), "mine", 1);

        MvcResult r = sessions("?node=" + host + "-다른노드");

        assertThat(read(r, "$[*].loginAccount")).isEmpty();
    }

    @Test
    void 접속이_없으면_빈_목록이다() throws Exception {
        assertThat(read(sessions("?node=" + host), "$[*].loginAccount")).isEmpty();
    }
}
