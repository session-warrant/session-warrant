package io.seswar.warrant.identity;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Keycloak 그룹 → 역할. 토큰의 {@code groups} claim(realm 의 group mapper 가 싣는다)을 읽는다.
 * 감사자는 발급 권한이 없다 — 감사자가 발급할 수 있으면 감사가 아니다.
 *
 * <p>그룹은 역할과 별개로 {@code GROUP_<이름>} 권한으로도 남긴다 — 정책별 승인 그룹(V7)이 그걸 본다.
 */
public class KeycloakGroups {

    static final Map<String, String> ROLE_OF = Map.of(
            "warrant-requesters", "ROLE_REQUESTER",
            "warrant-approvers", "ROLE_APPROVER",
            "warrant-auditors", "ROLE_AUDITOR");

    /** 그룹 권한의 접두사. {@code CurrentSubject.groups} 가 이걸 떼어 그룹 이름으로 되돌린다. */
    public static final String GROUP_PREFIX = "GROUP_";

    public Collection<GrantedAuthority> forClaims(Map<String, Object> claims) {
        Set<GrantedAuthority> out = new HashSet<>();
        if (claims.get("groups") instanceof List<?> groups) {
            for (Object g : groups) {
                String name = String.valueOf(g).replaceFirst("^/", "");
                String role = ROLE_OF.get(name);
                if (role != null) {
                    out.add(new SimpleGrantedAuthority(role));
                }
                if (!name.isBlank()) {
                    out.add(new SimpleGrantedAuthority(GROUP_PREFIX + name));
                }
            }
        }
        return out;
    }

    // Called by the resource server for Bearer tokens (curl, scripts).
    public Converter<Jwt, Collection<GrantedAuthority>> forJwt() {
        return jwt -> forClaims(jwt.getClaims());
    }

    // Called by oauth2Login after the console login: replaces the default OIDC_USER/SCOPE_* authorities.
    public GrantedAuthoritiesMapper forLogin() {
        return authorities -> {
            Set<GrantedAuthority> out = new HashSet<>();
            for (GrantedAuthority a : authorities) {
                if (a instanceof OidcUserAuthority oidc) {
                    out.addAll(forClaims(oidc.getIdToken().getClaims()));
                }
            }
            return out;
        };
    }
}
