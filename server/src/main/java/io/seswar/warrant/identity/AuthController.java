package io.seswar.warrant.identity;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * 콘솔 로그인 (dev 프로필). 이메일 · 비밀번호로 세션을 만든다. 「나」는 MeController, 로그아웃은 SecurityConfig.
 * oidc 프로필에서는 이 컨트롤러가 없다 — 로그인은 Keycloak 이 받는다.
 */
@Profile("dev")
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authentication;
    private final CurrentSubject current;
    private final SecurityContextRepository contexts = new HttpSessionSecurityContextRepository();

    public record LoginRequest(String email, String password) {
    }


    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest body, HttpServletRequest req, HttpServletResponse res) {
        Authentication auth;
        try {
            auth = authentication.authenticate(
                    UsernamePasswordAuthenticationToken.unauthenticated(body.email(), body.password()));
        } catch (AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "wrong email or password"));
        }
        // A new session id on login, so a session id planted before login is useless afterwards.
        if (req.getSession(false) != null) {
            req.changeSessionId();
        }
        SecurityContext ctx = SecurityContextHolder.createEmptyContext();
        ctx.setAuthentication(auth);
        SecurityContextHolder.setContext(ctx);
        contexts.saveContext(ctx, req, res);
        return ResponseEntity.ok(new MeController.Me(auth.getName(),
                current.find(auth).map(SubjectController.SubjectView::of).orElse(null)));
    }

}
