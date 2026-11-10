package io.seswar.warrant.identity;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * oidc 프로필 설정 ({@code warrant.oidc}, application-oidc.yml). Keycloak realm 하나와 서버용 클라이언트 하나.
 * 엔드포인트는 Keycloak 규칙으로 issuer 에서 만든다 — 기동할 때 Keycloak 에 묻지 않으므로 서버가 먼저 떠도 된다.
 */
@ConfigurationProperties("warrant.oidc")
public record OidcSettings(String issuer, String clientId, String clientSecret, String consoleUrl) {

    public String endpoint(String path) {
        return issuer + "/protocol/openid-connect/" + path;
    }

    /** 로그아웃할 때 Keycloak 세션도 끝낸다 — 안 끝내면 다음 로그인이 비밀번호 없이 지나간다. */
    public String logoutUrl() {
        return endpoint("logout") + "?client_id=" + clientId + "&post_logout_redirect_uri="
                + java.net.URLEncoder.encode(consoleUrl, java.nio.charset.StandardCharsets.UTF_8);
    }
}
