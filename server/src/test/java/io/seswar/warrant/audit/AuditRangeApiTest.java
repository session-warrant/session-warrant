package io.seswar.warrant.audit;

import com.jayway.jsonpath.JsonPath;
import io.seswar.warrant.node.NodeRegistry;
import io.seswar.warrant.proto.AgentProtos.AuditBatch;
import io.seswar.warrant.proto.AuditProtos;
import io.seswar.warrant.proto.AuditProtos.Hook;
import io.seswar.warrant.proto.AuditProtos.Origin;
import io.seswar.warrant.proto.AuditProtos.Verdict;
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
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

// 대시보드 「구간 선택」: 고른 기간의 막대별 집계와, 그 기간의 판정 기록(최신 순)을 준다.
@SpringBootTest(properties = "spring.grpc.server.port=0")
@AutoConfigureMockMvc
@ActiveProfiles("dev")
@Testcontainers
class AuditRangeApiTest {

    @Container
    @ServiceConnection
    static PostgreSQLContainer postgres = new PostgreSQLContainer("postgres:18");

    static final String ALICE = "alice@example.com", PW = "pw";
    // A fixed day far from other tests' rows, so ranges here see only what these tests wrote.
    static final Instant DAY = Instant.parse("2031-03-10T00:00:00+09:00");

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

    String host;
    UUID node;
    long nextSeq = 1;

    @BeforeEach
    void node() {
        host = "node-" + UUID.randomUUID();
        node = nodes.register("dev:" + host, new NodeRegistry.Report(host, "6.8", true, "test", Set.of(), null, 9)).nodeId();
    }

    // One kernel record at DAY + `minutes`.
    void arrive(long minutes, Hook hook, Verdict verdict, Origin origin, long warrantId) {
        Instant at = DAY.plusSeconds(minutes * 60);
        long seq = nextSeq++;
        var b = AuditProtos.AuditEvent.newBuilder()
                .setNodeSeq(seq).setWallTsUnixNs(at.getEpochSecond() * 1_000_000_000L).setWarrantId(warrantId)
                .setHook(hook).setVerdict(verdict).setMode(WarrantProtos.Mode.MODE_DRYRUN).setOrigin(origin)
                .setTagSource(AuditProtos.TagSource.TAG_CGROUP);
        var ref = AuditProtos.FileRef.newBuilder().setDev(2049).setIno(minutes);
        switch (hook) {
            case HOOK_BPRM_CHECK_SECURITY -> b.setExec(AuditProtos.ExecEvent.newBuilder().setFile(ref));
            case HOOK_SCHED_PROCESS_FORK -> b.setFork(AuditProtos.ForkEvent.newBuilder().setChildPid(41));
            default -> b.setFileWrite(AuditProtos.FileWriteEvent.newBuilder().setFile(ref));
        }
        ingest.ingest(node, AuditProtoMapper.toBatch(node,
                AuditBatch.newBuilder().setSeqEpoch(9).setLastNodeSeq(seq).addEvents(b.build()).build()));
    }

    void lsm(long minutes, Hook hook, Verdict verdict) {
        arrive(minutes, hook, verdict, Origin.ORIGIN_LSM, 8);
    }

    MvcResult call(String url) throws Exception {
        return mvc.perform(get(url).with(httpBasic(ALICE, PW))).andExpect(status().isOk()).andReturn();
    }

    String day(long minutes) {
        return DAY.plusSeconds(minutes * 60).toString();
    }

    @Test
    void 기간을_막대로_나눠_훅_판정별로_센다() throws Exception {
        lsm(1, Hook.HOOK_FILE_OPEN, Verdict.VERDICT_WOULD_DENY);
        lsm(2, Hook.HOOK_FILE_OPEN, Verdict.VERDICT_WOULD_DENY);
        lsm(3, Hook.HOOK_BPRM_CHECK_SECURITY, Verdict.VERDICT_ALLOW);
        lsm(7, Hook.HOOK_FILE_OPEN, Verdict.VERDICT_DENY);
        lsm(20, Hook.HOOK_FILE_OPEN, Verdict.VERDICT_DENY); // after `to`

        String json = call("/api/audit/summary?from=" + day(0) + "&to=" + day(10) + "&bucketSeconds=300&node=" + host)
                .getResponse().getContentAsString();

        List<Map<String, Object>> rows = JsonPath.read(json, "$");
        assertThat(rows).extracting(r -> r.get("t") + " " + r.get("hook") + " " + r.get("verdict") + " " + r.get("n"))
                .containsExactlyInAnyOrder(
                        DAY + " HOOK_FILE_OPEN WOULD_DENY 2",
                        DAY + " HOOK_BPRM_CHECK_SECURITY ALLOW 1",
                        DAY.plusSeconds(300) + " HOOK_FILE_OPEN DENY 1");
    }

    // 하루 막대는 서울 자정에서 시작해야 날짜가 맞는다. UTC 자정이면 09시에 날짜가 바뀐다.
    @Test
    void 막대_경계는_요청한_기준_시각에_맞춘다() throws Exception {
        lsm(8 * 60, Hook.HOOK_FILE_OPEN, Verdict.VERDICT_DENY);      // 08:00 KST — UTC 로는 전날
        lsm(23 * 60, Hook.HOOK_FILE_OPEN, Verdict.VERDICT_DENY);     // 23:00 KST

        String seoulMidnight = "2000-01-02T15:00:00Z"; // 2000-01-03 00:00 KST, as the dashboard sends it
        String json = call("/api/audit/summary?from=" + day(0) + "&to=" + day(24 * 60) + "&bucketSeconds=86400&origin="
                + seoulMidnight + "&node=" + host).getResponse().getContentAsString();

        assertThat(JsonPath.<List<String>>read(json, "$[*].t")).containsExactly(DAY.toString());
        assertThat(JsonPath.<List<Integer>>read(json, "$[*].n")).containsExactly(2);
    }

    // kprobe 미러는 같은 판정을 한 번 더 센다. fork 는 판정이 아니다. 무영장 기록은 따로 표시한다.
    @Test
    void 집계는_LSM_판정만_세고_영장_여부를_구분한다() throws Exception {
        lsm(1, Hook.HOOK_FILE_OPEN, Verdict.VERDICT_WOULD_DENY);
        arrive(1, Hook.HOOK_FILE_OPEN, Verdict.VERDICT_WOULD_DENY, Origin.ORIGIN_KPROBE, 8);
        arrive(1, Hook.HOOK_SCHED_PROCESS_FORK, Verdict.VERDICT_ALLOW, Origin.ORIGIN_LSM, 8);
        arrive(1, Hook.HOOK_FILE_OPEN, Verdict.VERDICT_WOULD_DENY, Origin.ORIGIN_LSM, 0);

        String json = call("/api/audit/summary?from=" + day(0) + "&to=" + day(5) + "&bucketSeconds=300&node=" + host)
                .getResponse().getContentAsString();

        List<Map<String, Object>> rows = JsonPath.read(json, "$");
        assertThat(rows).extracting(r -> r.get("hook") + " " + r.get("warranted") + " " + r.get("n"))
                .containsExactlyInAnyOrder("HOOK_FILE_OPEN true 1", "HOOK_FILE_OPEN false 1");
    }

    @Test
    void 막대가_너무_많거나_기간이_거꾸로면_거부한다() throws Exception {
        mvc.perform(get("/api/audit/summary?from=" + day(0) + "&to=" + day(60 * 24 * 30) + "&bucketSeconds=1")
                .with(httpBasic(ALICE, PW))).andExpect(status().isBadRequest());
        mvc.perform(get("/api/audit/summary?from=" + day(10) + "&to=" + day(0) + "&bucketSeconds=60")
                .with(httpBasic(ALICE, PW))).andExpect(status().isBadRequest());
    }

    // 구간 화면의 표: 그 기간의 판정 기록만, 최신 순. 한도에 걸리면 전체 건수로 잘렸다는 걸 알린다.
    @Test
    void 구간의_판정_기록을_최신_순으로_주고_전체_건수를_알린다() throws Exception {
        lsm(1, Hook.HOOK_FILE_OPEN, Verdict.VERDICT_WOULD_DENY);
        lsm(2, Hook.HOOK_FILE_OPEN, Verdict.VERDICT_WOULD_DENY);
        lsm(3, Hook.HOOK_FILE_OPEN, Verdict.VERDICT_WOULD_DENY);
        arrive(3, Hook.HOOK_SCHED_PROCESS_FORK, Verdict.VERDICT_ALLOW, Origin.ORIGIN_LSM, 8);
        arrive(3, Hook.HOOK_FILE_OPEN, Verdict.VERDICT_WOULD_DENY, Origin.ORIGIN_KPROBE, 8);
        lsm(9, Hook.HOOK_FILE_OPEN, Verdict.VERDICT_WOULD_DENY); // at `until`: excluded

        MvcResult r = call("/api/audit/events?since=" + day(0) + "&until=" + day(9) + "&kind=verdict&limit=2&node=" + host);

        assertThat(JsonPath.<List<Integer>>read(r.getResponse().getContentAsString(), "$[*].inode")).containsExactly(3, 2);
        assertThat(r.getResponse().getHeader("X-Audit-Total")).isEqualTo("3");
    }
}
