package io.seswar.warrant.identity;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

/**
 * dev 프로필의 콘솔 로그인 계정 ({@code warrant.dev.accounts}, application-dev.yml).
 * OIDC 가 붙기 전까지의 대역이다 — 운영에는 로컬 계정을 두지 않는다. 비밀번호는 {@code {bcrypt}} 해시다.
 */
@ConfigurationProperties("warrant.dev")
public record DevAccounts(List<Account> accounts) {

    public record Account(String email, String password) {
    }

    public List<Account> accounts() {
        return accounts == null ? List.of() : accounts;
    }
}
