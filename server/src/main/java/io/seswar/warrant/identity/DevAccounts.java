package io.seswar.warrant.identity;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

/**
 * dev 프로필의 콘솔 로그인 계정 ({@code warrant.dev.accounts}, application-dev.yml).
 * OIDC 가 붙기 전까지의 대역이다 — 운영에는 로컬 계정을 두지 않는다. 비밀번호는 {@code {bcrypt}} 해시다.
 */
@ConfigurationProperties("warrant.dev")
public record DevAccounts(List<Account> accounts) {

    /** {@code groups} 는 Keycloak 그룹 대역 — 정책별 승인 그룹(V7)을 dev 에서도 시험할 수 있게. 역할은 셋 다 받는다. */
    public record Account(String email, String password, List<String> groups) {
        public List<String> groups() {
            return groups == null ? List.of() : groups;
        }
    }

    public List<Account> accounts() {
        return accounts == null ? List.of() : accounts;
    }
}
