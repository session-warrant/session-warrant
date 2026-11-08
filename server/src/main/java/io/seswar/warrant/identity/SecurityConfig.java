package io.seswar.warrant.identity;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;

/**
 * <b>자체 회원가입을 만들지 않는다.</b> 조직 신원 매핑이 제품 핵심이므로
 * OIDC 공급자(Keycloak)를 붙이고, {@code sub} 가 그대로 {@code subject_id} 의 출처가 된다(기술 스택 §06).
 * 여기에 로컬 계정을 만드는 순간 "누가"의 신뢰도가 그 계정 수준으로 떨어진다.
 */
@Configuration
@EnableWebSecurity
@EnableConfigurationProperties(DevAccounts.class)
public class SecurityConfig {

    // Called by Spring Security at startup.
    // Health is public; everything else is closed until OIDC login is wired (oidc profile).
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth
                .requestMatchers("/actuator/health", "/actuator/health/**").permitAll()
                .anyRequest().authenticated());
        return http.build();
    }

    // Called by Spring Security only with the dev profile: console login with the accounts in application-dev.yml.
    // The dashboard holds a session cookie, so CSRF stays on (token in the XSRF-TOKEN cookie, echoed as X-XSRF-TOKEN).
    // curl sends Basic and no cookie; such a request cannot be forged by another tab, so it skips CSRF.
    // Unauthenticated calls get a bare 401, never a Basic challenge that would pop a browser dialog.
    @Bean
    @Order(0)
    @Profile("dev")
    SecurityFilterChain devApi(HttpSecurity http) throws Exception {
        HttpStatusEntryPoint unauthorized = new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED);
        CsrfTokenRequestAttributeHandler csrfHandler = new CsrfTokenRequestAttributeHandler();
        csrfHandler.setCsrfRequestAttributeName(null); // load the token on every request so the cookie is always set
        http.securityMatcher("/api/**")
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/login", "/api/signing-key").permitAll()
                        .anyRequest().authenticated())
                .httpBasic(basic -> basic.authenticationEntryPoint(unauthorized))
                .exceptionHandling(e -> e.authenticationEntryPoint(unauthorized))
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        .csrfTokenRequestHandler(csrfHandler)
                        .ignoringRequestMatchers(req -> req.getHeader("Authorization") != null))
                .logout(logout -> logout
                        .logoutUrl("/api/auth/logout")
                        .logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler(HttpStatus.NO_CONTENT)));
        return http.build();
    }

    @Bean
    @Profile("dev")
    UserDetailsService devUsers(DevAccounts accounts) {
        return new InMemoryUserDetailsManager(accounts.accounts().stream()
                .map(a -> User.withUsername(a.email()).password(a.password()).roles("USER").build())
                .toList());
    }

    // Called by AuthController.login. Passwords are stored as {bcrypt} hashes.
    @Bean
    @Profile("dev")
    AuthenticationManager devAuthentication(UserDetailsService users) {
        PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(users);
        provider.setPasswordEncoder(encoder);
        return new ProviderManager(provider);
    }

    // 남은 것:
    // /api/**    → OIDC 인증 필요 (oauth2Login · oauth2ResourceServer)
    // /api/approvals/** POST → APPROVER. 콘솔은 세션 쿠키로 붙으므로 CSRF 보호를 끄지 말 것 —
    //                          끄면 승인자가 연 다른 탭이 승인 버튼을 대신 누를 수 있다
    //
    // 권한 분리:
    //   REQUESTER  영장 요청
    //   APPROVER   승인 · 연장 · 회수
    //   AUDITOR    감사 조회 전용 — 발급 권한 없음. 감사자가 발급할 수 있으면 감사가 아니다
    //   OPERATOR   노드 · 정책 관리
}
