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
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * 콘솔 로그인 (dev 프로필). 이메일 · 비밀번호로 세션을 만든다. 로그아웃은 SecurityConfig 의 logout 이 맡는다.
 * 로그인한 이메일과 principal 이 같은 주체가 콘솔의 「나」 — 영장 신청자가 된다.
 */
@Profile("dev")
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authentication;
    private final SubjectRepository subjects;
    private final SecurityContextRepository contexts = new HttpSessionSecurityContextRepository();

    public record LoginRequest(String email, String password) {
    }

    public record Me(String email, SubjectController.SubjectView subject) {
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
        return ResponseEntity.ok(me(auth));
    }

    @GetMapping("/me")
    public Me me(Authentication auth) {
        return new Me(auth.getName(), subjects.findByPrincipal(auth.getName()).map(SubjectController.SubjectView::of).orElse(null));
    }
}
