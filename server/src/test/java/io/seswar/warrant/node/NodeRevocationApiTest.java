package io.seswar.warrant.node;

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
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.nio.file.Files;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

// POST /api/nodes/{id}/revoke — 사유 필수, 한 번만, 누가 했는지 남는다.
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = "spring.grpc.server.port=0")
@AutoConfigureMockMvc
@ActiveProfiles("dev")
@Testcontainers
class NodeRevocationApiTest {

    @Container
    @ServiceConnection
    static PostgreSQLContainer postgres = new PostgreSQLContainer("postgres:18");

    static final String OPS = "ops@test", PW = "pw";

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry r) throws Exception {
        String path = Files.createTempDirectory("sk").resolve("signing.key").toString();
        r.add("warrant.signing.key-path", () -> path);
        r.add("warrant.dev.accounts[0].email", () -> OPS);
        r.add("warrant.dev.accounts[0].password", () -> "{noop}" + PW);
    }

    @Autowired MockMvc mvc;
    @Autowired NodeRegistry registry;
    @Autowired NodeRepository nodes;
    @Autowired SubjectRepository subjects;

    UUID node;
    String host;

    @BeforeEach
    void seed() {
        if (subjects.findByPrincipal(OPS).isEmpty()) {
            subjects.saveAndFlush(Subject.of("oidc|" + OPS, OPS, "ec2-user", List.of()));
        }
        host = "node-" + UUID.randomUUID();
        node = registry.register("dev:" + host, new NodeRegistry.Report(host, "6.8", true, "test", Set.of(), null, 9)).nodeId();
    }

    @Test
    void 폐기하면_목록에_시각과_사유가_남고_누가_했는지_기록된다() throws Exception {
        mvc.perform(post("/api/nodes/" + node + "/revoke").with(httpBasic(OPS, PW))
                        .contentType(MediaType.APPLICATION_JSON).content("{\"reason\":\"인증서 유출\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.revokedAt").isNotEmpty())
                .andExpect(jsonPath("$.revokeReason").value("인증서 유출"));

        mvc.perform(get("/api/nodes").with(httpBasic(OPS, PW)))
                .andExpect(jsonPath("$[?(@.id == '%s')].revokeReason".formatted(node)).value("인증서 유출"));
        assertThat(nodes.findById(node).orElseThrow().getRevokedBy())
                .isEqualTo(subjects.findByPrincipal(OPS).orElseThrow().getId());
    }

    @Test
    void 사유가_없으면_400이고_폐기되지_않는다() throws Exception {
        mvc.perform(post("/api/nodes/" + node + "/revoke").with(httpBasic(OPS, PW))
                        .contentType(MediaType.APPLICATION_JSON).content("{\"reason\":\" \"}"))
                .andExpect(status().isBadRequest());
        assertThat(nodes.findById(node).orElseThrow().isRevoked()).isFalse();
    }

    @Test
    void 이미_폐기된_노드를_다시_폐기하면_409다() throws Exception {
        String body = "{\"reason\":\"반납\"}";
        mvc.perform(post("/api/nodes/" + node + "/revoke").with(httpBasic(OPS, PW))
                .contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isOk());
        mvc.perform(post("/api/nodes/" + node + "/revoke").with(httpBasic(OPS, PW))
                .contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isConflict());
    }

    @Test
    void 폐기된_노드는_다시_등록되지_않는다() throws Exception {
        mvc.perform(post("/api/nodes/" + node + "/revoke").with(httpBasic(OPS, PW))
                .contentType(MediaType.APPLICATION_JSON).content("{\"reason\":\"반납\"}")).andExpect(status().isOk());

        org.assertj.core.api.Assertions.assertThatThrownBy(() -> registry.register("dev:" + host,
                        new NodeRegistry.Report(host, "6.8", true, "test", Set.of(), null, 9)))
                .isInstanceOf(NodeRevokedException.class);
    }
}
