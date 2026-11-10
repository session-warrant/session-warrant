package io.seswar.warrant.identity;

import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.nio.file.Files;
import java.util.List;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

// Console login in the dev profile: a configured account, a session cookie, CSRF on.
@SpringBootTest(properties = "spring.grpc.server.port=0")
@AutoConfigureMockMvc
@ActiveProfiles("dev")
@Testcontainers
class AuthApiTest {

    @Container
    @ServiceConnection
    static PostgreSQLContainer postgres = new PostgreSQLContainer("postgres:18");

    @DynamicPropertySource
    static void signingKey(DynamicPropertyRegistry r) throws Exception {
        String path = Files.createTempDirectory("sk").resolve("signing.key").toString();
        r.add("warrant.signing.key-path", () -> path);
    }

    static final String EMAIL = "dev@example.com";
    static final String PASSWORD = "1234";

    @Autowired MockMvc mvc;
    @Autowired SubjectRepository subjects;

    // The SPA gets the CSRF token from the XSRF-TOKEN cookie and echoes it in a header.
    Cookie csrfCookie(MockHttpSession session) throws Exception {
        MvcResult r = mvc.perform(get("/api/auth/me").session(session)).andReturn();
        return r.getResponse().getCookie("XSRF-TOKEN");
    }

    MockHttpSession login(String email, String password, int expect) throws Exception {
        MockHttpSession session = new MockHttpSession();
        Cookie xsrf = csrfCookie(session);
        mvc.perform(post("/api/auth/login").session(session).cookie(xsrf).header("X-XSRF-TOKEN", xsrf.getValue())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"%s\",\"password\":\"%s\"}".formatted(email, password)))
                .andExpect(status().is(expect));
        return session;
    }

    @Test
    void 로그인하지_않으면_API는_401이다() throws Exception {
        mvc.perform(get("/api/warrants")).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/auth/me")).andExpect(status().isUnauthorized());
    }

    @Test
    void 맞는_이메일과_비밀번호로_로그인하면_세션으로_API를_쓴다() throws Exception {
        MockHttpSession session = login(EMAIL, PASSWORD, 200);

        mvc.perform(get("/api/auth/me").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value(EMAIL));
        mvc.perform(get("/api/warrants").session(session)).andExpect(status().isOk());
    }

    @Test
    void 비밀번호가_틀리면_로그인되지_않는다() throws Exception {
        MockHttpSession session = login(EMAIL, "wrong", 401);

        mvc.perform(get("/api/auth/me").session(session)).andExpect(status().isUnauthorized());
    }

    // 로그인한 이메일과 같은 principal 의 주체가 「나」다. 신청자가 된다.
    @Test
    void 로그인한_사람의_주체를_알려준다() throws Exception {
        subjects.findByPrincipal(EMAIL).orElseGet(() -> subjects.saveAndFlush(
                Subject.of("oidc|" + EMAIL, EMAIL, "jonnykim", List.of("SHA256:test-" + System.nanoTime()))));
        MockHttpSession session = login(EMAIL, PASSWORD, 200);

        mvc.perform(get("/api/auth/me").session(session))
                .andExpect(jsonPath("$.subject.principal").value(EMAIL))
                .andExpect(jsonPath("$.subject.kernelSubjectId").isNumber());
    }

    @Test
    void 로그아웃하면_세션이_끊긴다() throws Exception {
        MockHttpSession session = login(EMAIL, PASSWORD, 200);
        Cookie xsrf = csrfCookie(session);

        mvc.perform(post("/api/auth/logout").session(session).cookie(xsrf).header("X-XSRF-TOKEN", xsrf.getValue()))
                .andExpect(status().isNoContent());
        mvc.perform(get("/api/auth/me").session(session)).andExpect(status().isUnauthorized());
    }

    // 세션 쿠키로 붙은 요청은 CSRF 토큰이 있어야 바꾸는 요청을 할 수 있다 — 다른 탭이 대신 누르지 못하게.
    @Test
    void 세션으로_보내는_POST에_CSRF_토큰이_없으면_403이다() throws Exception {
        MockHttpSession session = login(EMAIL, PASSWORD, 200);

        mvc.perform(post("/api/policies").session(session).contentType(MediaType.APPLICATION_JSON).content("{\"name\":\"x\"}"))
                .andExpect(status().isForbidden());
    }

    // curl 은 쿠키 없이 Basic 으로 붙는다. 쿠키가 없으니 CSRF 대상이 아니다.
    @Test
    void curl은_Basic_인증으로_쓴다() throws Exception {
        mvc.perform(get("/api/warrants").with(httpBasic(EMAIL, PASSWORD))).andExpect(status().isOk());
        mvc.perform(post("/api/policies").with(httpBasic(EMAIL, PASSWORD))
                        .contentType(MediaType.APPLICATION_JSON).content("{\"name\":\"basic\"}"))
                .andExpect(status().isCreated());
        mvc.perform(get("/api/warrants").with(httpBasic(EMAIL, "wrong"))).andExpect(status().isUnauthorized());
    }

    @Test
    void 노드에_심을_공개키는_로그인_없이_받는다() throws Exception {
        mvc.perform(get("/api/signing-key")).andExpect(status().isOk());
    }
}
