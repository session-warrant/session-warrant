package io.seswar.warrant.identity;

import lombok.RequiredArgsConstructor;
import org.springframework.core.env.Environment;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.Map;

/** 로그인 방식과 「나」. dev · oidc 둘 다에서 쓴다. 이메일 · 비밀번호 로그인은 dev 의 AuthController 가 받는다. */
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class MeController {

    private final CurrentSubject current;
    private final Environment env;
    private final OidcSettings oidc;

    public record Me(String email, SubjectController.SubjectView subject) {
    }

    /** 대시보드가 401 을 받으면 이걸 보고 이메일 폼을 띄울지 Keycloak 으로 보낼지 정한다. */
    @GetMapping("/config")
    public Map<String, String> config() {
        return Arrays.asList(env.getActiveProfiles()).contains("oidc")
                ? Map.of("mode", "oidc", "loginUrl", "/oauth2/authorization/keycloak", "logoutUrl", oidc.logoutUrl())
                : Map.of("mode", "dev");
    }

    @GetMapping("/me")
    public Me me(Authentication auth) {
        return new Me(CurrentSubject.identity(auth).email(),
                current.find(auth).map(SubjectController.SubjectView::of).orElse(null));
    }
}
