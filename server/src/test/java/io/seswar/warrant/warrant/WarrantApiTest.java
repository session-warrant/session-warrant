package io.seswar.warrant.warrant;

import io.seswar.warrant.identity.Subject;
import io.seswar.warrant.identity.SubjectRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.nio.file.Files;
import java.util.UUID;

import static org.hamcrest.Matchers.startsWith;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

// The whole server: REST over MockMvc, real PostgreSQL, gRPC on a random port.
@SpringBootTest(properties = "spring.grpc.server.port=0")
@AutoConfigureMockMvc
@ActiveProfiles("dev")
@Testcontainers
class WarrantApiTest {

    @Container
    @ServiceConnection
    static PostgreSQLContainer postgres = new PostgreSQLContainer("postgres:18");

    static final String ALICE = "alice@example.com", BOB = "bob@example.com", PW = "pw";

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry r) throws Exception {
        String path = Files.createTempDirectory("sk").resolve("signing.key").toString();
        r.add("warrant.signing.key-path", () -> path);
        r.add("warrant.dev.accounts[0].email", () -> ALICE);
        r.add("warrant.dev.accounts[0].password", () -> "{noop}" + PW);
        r.add("warrant.dev.accounts[1].email", () -> BOB);
        r.add("warrant.dev.accounts[1].password", () -> "{noop}" + PW);
    }

    @Autowired MockMvc mvc;
    @Autowired SubjectRepository subjects;

    @BeforeEach
    void seed() {
        for (String email : java.util.List.of(ALICE, BOB)) {
            if (subjects.findByPrincipal(email).isEmpty()) {
                subjects.saveAndFlush(Subject.of("oidc|" + email, email, "ec2-user", java.util.List.of("SHA256:" + email)));
            }
        }
    }

    static MockHttpServletRequestBuilder as(String who, MockHttpServletRequestBuilder b) {
        return b.with(httpBasic(who, PW));
    }

    String postJson(String who, String url, String body) throws Exception {
        return mvc.perform(as(who, post(url)).contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
    }

    static String field(String json, String name) {
        int i = json.indexOf("\"" + name + "\":\"") + name.length() + 4;
        return json.substring(i, json.indexOf('"', i));
    }

    String policy() throws Exception {
        return field(postJson(ALICE, "/api/policies", """
                {"name": "ops", "execRules": ["/usr/bin/ls"],
                 "writeRules": [{"path": "/tmp", "recursive": true, "effect": "ALLOW"}],
                 "netRules": [{"cidr": "10.0.0.0/8", "port": 443, "proto": "TCP"}]}"""), "id");
    }

    @Test
    void 신청하고_다른_사람이_승인하고_회수한다() throws Exception {
        String id = field(postJson(ALICE, "/api/warrants", """
                {"loginAccount": "ec2-user", "reason": "INC-1", "targetHosts": ["node-1"], "policyId": "%s",
                 "duration": "PT15M", "mode": "DRYRUN"}""".formatted(policy())), "id");

        mvc.perform(as(BOB, post("/api/approvals/" + id + "/approve"))).andExpect(status().isOk());

        mvc.perform(as(ALICE, get("/api/warrants/" + id)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.revision").value(1))
                .andExpect(jsonPath("$.state").value("ISSUED"))
                .andExpect(jsonPath("$.warrantId").isNumber())
                .andExpect(jsonPath("$.targetHosts[0]").value("node-1"));

        mvc.perform(as(BOB, delete("/api/warrants/" + id)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.revision").value(2))
                .andExpect(jsonPath("$.state").value("REVOKED"))
                .andExpect(jsonPath("$.revoked").value(true));
    }

    @Test
    void 기간을_안_주면_기본_30분이다() throws Exception {
        mvc.perform(as(ALICE, post("/api/warrants")).contentType(MediaType.APPLICATION_JSON).content("""
                        {"loginAccount": "ec2-user", "reason": "점검", "targetHosts": ["node-1"], "policyId": "%s"}"""
                        .formatted(policy())))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.durationSeconds").value(1800));
    }

    @Test
    void 없는_정책으로_신청하면_400이다() throws Exception {
        mvc.perform(as(ALICE, post("/api/warrants")).contentType(MediaType.APPLICATION_JSON).content("""
                        {"loginAccount": "ec2-user", "reason": "r", "targetHosts": ["node-1"], "policyId": "%s"}"""
                        .formatted(UUID.randomUUID())))
                .andExpect(status().isBadRequest());
    }

    @Test
    void 없는_영장은_404다() throws Exception {
        mvc.perform(as(ALICE, get("/api/warrants/" + UUID.randomUUID()))).andExpect(status().isNotFound());
    }

    // 대시보드가 노드 목록 · 무영장 세션 · 유실 구간을 읽는다. 감사 스트림으로 들어온 것만 있다.
    @Test
    void 노드와_무영장_세션과_유실_구간을_목록으로_준다() throws Exception {
        mvc.perform(as(ALICE, get("/api/nodes"))).andExpect(status().isOk()).andExpect(jsonPath("$").isArray());
        mvc.perform(as(ALICE, get("/api/audit/unwarranted"))).andExpect(status().isOk()).andExpect(jsonPath("$").isArray());
        mvc.perform(as(ALICE, get("/api/audit/gaps"))).andExpect(status().isOk()).andExpect(jsonPath("$").isArray());
    }

    // 노드는 이 본문을 /etc/warrantd/keys/<X-Key-Id>.pem 으로 저장한다.
    @Test
    void 서명_공개키를_PEM으로_준다() throws Exception {
        mvc.perform(get("/api/signing-key"))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Key-Id", "central"))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.content()
                        .string(startsWith("-----BEGIN PUBLIC KEY-----")));
    }
}
