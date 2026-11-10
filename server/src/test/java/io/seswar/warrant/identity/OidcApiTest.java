package io.seswar.warrant.identity;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.nio.file.Files;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.startsWith;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oidcLogin;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

// The oidc profile without a running Keycloak: tokens and logins are stood in by spring-security-test.
// Keycloak is never contacted, which also proves the server starts before Keycloak does.
@SpringBootTest(properties = {"spring.grpc.server.port=0", "spring.grpc.server.inprocess.name=oidc-test"})
@AutoConfigureMockMvc
@ActiveProfiles("oidc")
@Testcontainers
class OidcApiTest {

    @Container
    @ServiceConnection
    static PostgreSQLContainer postgres = new PostgreSQLContainer("postgres:18");

    static final String ISSUER = "http://keycloak.test/realms/warrant";

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry r) throws Exception {
        String path = Files.createTempDirectory("sk").resolve("signing.key").toString();
        r.add("warrant.signing.key-path", () -> path);
        r.add("warrant.oidc.issuer", () -> ISSUER);
    }

    @Autowired MockMvc mvc;
    @Autowired SubjectRepository subjects;

    // A Keycloak access token: sub, verified email, groups.
    static RequestPostProcessor token(String sub, String email, String... groups) {
        return jwt().jwt(j -> j.subject(sub).claim("email", email).claim("email_verified", true)
                        .claim("groups", List.of(groups)))
                .authorities(new KeycloakGroups().forJwt());
    }

    String policy(RequestPostProcessor who) throws Exception {
        String body = mvc.perform(post("/api/policies").with(who).with(csrf())
                        .contentType(MediaType.APPLICATION_JSON).content("{\"name\":\"ops\"}"))
                .andExpect(status().isCreated()).andReturn().getResponse().getContentAsString();
        return body.substring(body.indexOf("\"id\":\"") + 6, body.indexOf("\"", body.indexOf("\"id\":\"") + 6));
    }

    // 노드(warrantd)는 사람 로그인 토큰이 없다. 노드 신원은 mTLS 로 따로 간다 — 그 전까지 gRPC 에 OIDC 를 요구하면
    // 승인한 영장이 노드로 안 내려가고 감사도 안 올라온다(2026-11-09, oidc 로 바꾸자 노드가 전부 Unauthenticated 였다).
    @Test
    void 노드의_gRPC는_OIDC_토큰을_요구하지_않는다() throws Exception {
        io.grpc.ManagedChannel ch = io.grpc.inprocess.InProcessChannelBuilder.forName("oidc-test").build();
        try {
            var it = io.seswar.warrant.proto.WarrantPushServiceGrpc.newBlockingStub(ch)
                    .withDeadlineAfter(5, java.util.concurrent.TimeUnit.SECONDS)
                    .subscribe(io.seswar.warrant.proto.AgentProtos.SubscribeRequest.newBuilder()
                            .setNode(io.seswar.warrant.proto.AgentProtos.NodeHello.newBuilder().setHostname("node-" + UUID.randomUUID()))
                            .build());
            assertThat(it.next().hasResyncComplete()).isTrue();
        } finally {
            ch.shutdownNow();
        }
    }

    @Test
    void 로그인하지_않으면_401이고_어디로_로그인하는지_알려준다() throws Exception {
        mvc.perform(get("/api/warrants")).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/auth/config"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.mode").value("oidc"))
                .andExpect(jsonPath("$.loginUrl").value("/oauth2/authorization/keycloak"));
    }

    // 브라우저는 Keycloak 로그인 페이지로 간다. PKCE 를 쓴다.
    @Test
    void 콘솔_로그인은_Keycloak으로_보낸다() throws Exception {
        mvc.perform(get("/oauth2/authorization/keycloak"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", startsWith(ISSUER + "/protocol/openid-connect/auth")))
                .andExpect(header().string("Location", containsString("code_challenge=")));
    }

    @Test
    void 처음_로그인하면_sub로_주체가_생긴다() throws Exception {
        String sub = UUID.randomUUID().toString();
        String email = "new-" + sub + "@example.com";

        mvc.perform(get("/api/auth/me").with(token(sub, email, "warrant-requesters")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.subject.principal").value(email));

        assertThat(subjects.findByOidcSubject(sub)).isPresent();
    }

    // dev 로그인 시절에 만든 주체가 있으면 같은 검증된 이메일로 이어 붙인다 — 새로 만들면 같은 사람이 둘이 된다.
    @Test
    void 같은_이메일의_기존_주체에_sub가_연결된다() throws Exception {
        String email = "legacy-" + UUID.randomUUID() + "@example.com";
        Subject old = subjects.saveAndFlush(Subject.of("legacy|" + email, email, "ec2-user", List.of()));
        String sub = UUID.randomUUID().toString();

        mvc.perform(get("/api/auth/me").with(token(sub, email, "warrant-requesters")))
                .andExpect(jsonPath("$.subject.id").value(old.getId().toString()));

        assertThat(subjects.findByOidcSubject(sub)).map(Subject::getId).contains(old.getId());
    }

    @Test
    void 그룹이_없으면_신청할_수_없다() throws Exception {
        RequestPostProcessor nobody = token(UUID.randomUUID().toString(), "nobody-" + UUID.randomUUID() + "@example.com");

        mvc.perform(post("/api/warrants").with(nobody).with(csrf()).contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isForbidden());
    }

    // 승인은 승인자 그룹만. 신청자 그룹만 가진 사람은 남의 신청도 승인하지 못한다.
    @Test
    void 신청자가_신청하고_승인자_그룹이_승인한다() throws Exception {
        RequestPostProcessor requester = token(UUID.randomUUID().toString(), "req-" + UUID.randomUUID() + "@example.com", "warrant-requesters");
        RequestPostProcessor otherRequester = token(UUID.randomUUID().toString(), "req2-" + UUID.randomUUID() + "@example.com", "warrant-requesters");
        RequestPostProcessor approver = token(UUID.randomUUID().toString(), "apr-" + UUID.randomUUID() + "@example.com", "warrant-approvers");

        String body = mvc.perform(post("/api/warrants").with(requester).with(csrf()).contentType(MediaType.APPLICATION_JSON).content("""
                        {"loginAccount": "ec2-user", "reason": "INC-9", "targetHosts": ["node-oidc"], "policyId": "%s"}"""
                        .formatted(policy(requester))))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
        String id = body.substring(body.indexOf("\"id\":\"") + 6, body.indexOf("\"", body.indexOf("\"id\":\"") + 6));

        mvc.perform(post("/api/approvals/" + id + "/approve").with(otherRequester).with(csrf()))
                .andExpect(status().isForbidden());
        mvc.perform(post("/api/approvals/" + id + "/approve").with(approver).with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.state").value("ISSUED"));
    }

    // 콘솔은 토큰이 아니라 로그인 세션(OidcUser)으로 붙는다. 같은 규칙이 그쪽에도 걸린다.
    @Test
    void 콘솔_로그인_세션으로도_나를_찾는다() throws Exception {
        String sub = UUID.randomUUID().toString();
        String email = "console-" + sub + "@example.com";
        OidcIdToken id = OidcIdToken.withTokenValue("id").subject(sub).claim("email", email).claim("email_verified", true)
                .claim("groups", List.of("warrant-approvers")).issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60)).build();

        mvc.perform(get("/api/auth/me").with(oidcLogin().idToken(t -> t.claims(c -> c.putAll(id.getClaims())))
                        .authorities(new KeycloakGroups().forClaims(id.getClaims()))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value(email));
    }
}
