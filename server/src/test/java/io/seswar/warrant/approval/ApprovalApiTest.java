package io.seswar.warrant.approval;

import io.seswar.warrant.identity.Subject;
import io.seswar.warrant.identity.SubjectRepository;
import io.seswar.warrant.signing.WarrantSigner;
import io.seswar.warrant.warrant.Warrant;
import io.seswar.warrant.warrant.WarrantRepository;
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
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.nio.file.Files;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

// Request → approve by someone else → signed and pushed. Self-approval is refused by the server, not the screen.
@SpringBootTest(properties = "spring.grpc.server.port=0")
@AutoConfigureMockMvc
@ActiveProfiles("dev")
@Testcontainers
class ApprovalApiTest {

    @Container
    @ServiceConnection
    static PostgreSQLContainer postgres = new PostgreSQLContainer("postgres:18");

    static final String REQUESTER = "requester@test", APPROVER = "approver@test", PW = "pw";

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry r) throws Exception {
        String path = Files.createTempDirectory("sk").resolve("signing.key").toString();
        r.add("warrant.signing.key-path", () -> path);
        r.add("warrant.dev.accounts[0].email", () -> REQUESTER);
        r.add("warrant.dev.accounts[0].password", () -> "{noop}" + PW);
        r.add("warrant.dev.accounts[1].email", () -> APPROVER);
        r.add("warrant.dev.accounts[1].password", () -> "{noop}" + PW);
    }

    @Autowired MockMvc mvc;
    @Autowired SubjectRepository subjects;
    @Autowired WarrantRepository warrants;
    @Autowired WarrantSigner signer;

    String policyId;
    String host;

    @BeforeEach
    void seed() throws Exception {
        for (String email : List.of(REQUESTER, APPROVER)) {
            if (subjects.findByPrincipal(email).isEmpty()) {
                subjects.saveAndFlush(Subject.of("oidc|" + email, email, "ec2-user", List.of("SHA256:" + email)));
            }
        }
        host = "node-" + UUID.randomUUID();
        String p = mvc.perform(post("/api/policies").with(httpBasic(REQUESTER, PW))
                        .contentType(MediaType.APPLICATION_JSON).content("{\"name\":\"ops\",\"execRules\":[\"/usr/bin/ls\"]}"))
                .andExpect(status().isCreated()).andReturn().getResponse().getContentAsString();
        policyId = field(p, "id");
    }

    static String field(String json, String name) {
        int i = json.indexOf("\"" + name + "\":\"") + name.length() + 4;
        return json.substring(i, json.indexOf('"', i));
    }

    String request(String as) throws Exception {
        String body = mvc.perform(post("/api/warrants").with(httpBasic(as, PW)).contentType(MediaType.APPLICATION_JSON).content("""
                        {"loginAccount": "ec2-user", "reason": "INC-7 점검", "targetHosts": ["%s"], "policyId": "%s",
                         "duration": "PT45M", "mode": "DRYRUN"}""".formatted(host, policyId)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.state").value("REQUESTED"))
                .andReturn().getResponse().getContentAsString();
        return field(body, "id");
    }

    @Test
    void 신청하면_승인_대기로_남고_노드로는_가지_않는다() throws Exception {
        String id = request(REQUESTER);

        Warrant w = warrants.findById(UUID.fromString(id)).orElseThrow();
        assertThat(w.getSignedPayload()).isNull();
        assertThat(w.getSubjectId()).isEqualTo(subjects.findByPrincipal(REQUESTER).orElseThrow().getId());
        assertThat(warrants.findActiveForHost(host, Instant.now())).isEmpty();

        mvc.perform(get("/api/approvals").with(httpBasic(APPROVER, PW)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.warrant.id == '%s')].approvable".formatted(id)).value(true));
        mvc.perform(get("/api/approvals").with(httpBasic(REQUESTER, PW)))
                .andExpect(jsonPath("$[?(@.warrant.id == '%s')].approvable".formatted(id)).value(false));
    }

    // 화면의 비활성 버튼은 집행이 아니다. 서버가 막는다.
    @Test
    void 본인_신청은_승인할_수_없다() throws Exception {
        String id = request(REQUESTER);

        mvc.perform(post("/api/approvals/" + id + "/approve").with(httpBasic(REQUESTER, PW)))
                .andExpect(status().isForbidden());
    }

    @Test
    void 다른_사람이_승인하면_그때부터_기간이_시작되고_서명된다() throws Exception {
        String id = request(REQUESTER);
        Instant before = Instant.now();

        mvc.perform(post("/api/approvals/" + id + "/approve").with(httpBasic(APPROVER, PW)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.state").value("ISSUED"))
                .andExpect(jsonPath("$.lineage[0].type").value("REQUESTED"))
                .andExpect(jsonPath("$.lineage[0].actor").value(REQUESTER))
                .andExpect(jsonPath("$.lineage[1].type").value("ISSUED"))
                .andExpect(jsonPath("$.lineage[1].actor").value(APPROVER));

        Warrant w = warrants.findById(UUID.fromString(id)).orElseThrow();
        assertThat(signer.verify(w.getSignedPayload(), w.getSignature())).isTrue();
        assertThat(w.getIssuedAt()).isAfterOrEqualTo(before);
        assertThat(Duration.between(w.getIssuedAt(), w.getExpiresAt())).isEqualTo(Duration.ofMinutes(45));
        assertThat(warrants.findActiveForHost(host, Instant.now())).extracting(Warrant::getId).containsExactly(w.getId());
    }

    // 이중 클릭 · 두 승인자 동시 승인이 중복 발급이 되지 않는다.
    @Test
    void 이미_처리된_신청을_다시_승인하면_409다() throws Exception {
        String id = request(REQUESTER);
        mvc.perform(post("/api/approvals/" + id + "/approve").with(httpBasic(APPROVER, PW))).andExpect(status().isOk());

        mvc.perform(post("/api/approvals/" + id + "/approve").with(httpBasic(APPROVER, PW)))
                .andExpect(status().isConflict());
    }

    @Test
    void 반려에는_사유가_필요하고_반려된_신청은_발급되지_않는다() throws Exception {
        String id = request(REQUESTER);

        mvc.perform(post("/api/approvals/" + id + "/reject").with(httpBasic(APPROVER, PW))
                        .contentType(MediaType.APPLICATION_JSON).content("{\"reason\":\" \"}"))
                .andExpect(status().isBadRequest());
        mvc.perform(post("/api/approvals/" + id + "/reject").with(httpBasic(APPROVER, PW))
                        .contentType(MediaType.APPLICATION_JSON).content("{\"reason\":\"범위가 넓다\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.state").value("REJECTED"))
                .andExpect(jsonPath("$.lineage[1].type").value("REJECTED"))
                .andExpect(jsonPath("$.lineage[1].reason").value("범위가 넓다"));

        mvc.perform(post("/api/approvals/" + id + "/approve").with(httpBasic(APPROVER, PW)))
                .andExpect(status().isConflict());
    }
}
