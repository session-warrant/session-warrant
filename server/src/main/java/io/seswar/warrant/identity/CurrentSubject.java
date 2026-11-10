package io.seswar.warrant.identity;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * 로그인한 사람의 주체. 신청자 · 승인자는 요청 본문이 아니라 여기서 온다 — 본문은 아무 이름이나 적을 수 있다.
 *
 * <p>OIDC: 신원은 {@code sub} 다(이메일은 바뀔 수 있다). 처음 보는 sub 면 주체를 만든다. 다만 검증된 같은
 * 이메일의 주체가 이미 있으면(dev 로그인 시절에 만든 것) 그 주체에 sub 를 잇는다 — 새로 만들면 같은 사람이 둘이 된다.
 * dev: 로그인한 이메일과 principal 이 같은 주체.
 */
@Component
@RequiredArgsConstructor
public class CurrentSubject {

    private final SubjectRepository subjects;

    /** 로그인 출처와 상관없이 「이 사람」의 이메일과 OIDC sub(dev 면 null). */
    public record Identity(String sub, String email, boolean emailVerified) {
    }

    public static Identity identity(Authentication auth) {
        Map<String, Object> claims = switch (auth.getPrincipal()) {
            case Jwt jwt -> jwt.getClaims();
            case OidcUser user -> user.getClaims();
            default -> null;
        };
        if (claims == null) {
            return new Identity(null, auth.getName(), true);
        }
        return new Identity((String) claims.get("sub"), (String) claims.get("email"),
                Boolean.TRUE.equals(claims.get("email_verified")));
    }

    // Called by WarrantController, ApprovalController and MeController. A login with no subject cannot request or decide.
    @Transactional
    public Subject require(Authentication auth) {
        return find(auth).orElseThrow(() ->
                new ResponseStatusException(HttpStatus.FORBIDDEN, "no subject for " + auth.getName()));
    }

    @Transactional
    public Optional<Subject> find(Authentication auth) {
        Identity id = identity(auth);
        if (id.sub() == null) {
            return subjects.findByPrincipal(id.email());
        }
        Optional<Subject> bySub = subjects.findByOidcSubject(id.sub());
        if (bySub.isPresent()) {
            return bySub;
        }
        if (id.email() == null) {
            return Optional.empty();
        }
        Optional<Subject> byEmail = id.emailVerified() ? subjects.findByPrincipal(id.email()) : Optional.empty();
        if (byEmail.isPresent()) {
            byEmail.get().linkOidc(id.sub());
            return byEmail;
        }
        return Optional.of(subjects.saveAndFlush(Subject.of(id.sub(), id.email(), null, List.of())));
    }
}
