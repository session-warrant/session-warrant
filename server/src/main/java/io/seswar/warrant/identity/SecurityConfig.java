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
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.http.HttpMethod;

/**
 * <b>자체 회원가입을 만들지 않는다.</b> 조직 신원 매핑이 제품 핵심이므로
 * OIDC 공급자(Keycloak)를 붙이고, {@code sub} 가 그대로 {@code subject_id} 의 출처가 된다(기술 스택 §06).
 * 여기에 로컬 계정을 만드는 순간 "누가"의 신뢰도가 그 계정 수준으로 떨어진다.
 */
@Configuration
@EnableWebSecurity
@EnableConfigurationProperties({DevAccounts.class, OidcSettings.class})
public class SecurityConfig {

    // Called by Spring Security at startup.
    // Health is public; everything else is closed unless the dev or oidc chain below takes the request.
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth
                .requestMatchers("/actuator/health", "/actuator/health/**").permitAll()
                .anyRequest().authenticated());
        return http.build();
    }

    /**
     * 역할 규칙 — dev · oidc 가 같은 규칙을 쓴다.
     * REQUESTER 신청 · APPROVER 승인 · 반려 · 회수 · AUDITOR 조회만(발급 권한 없음). 자기 승인 금지는 ApprovalService 가 따로 막는다.
     */
    private static void rules(AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry auth) {
        auth.requestMatchers("/api/auth/login", "/api/auth/config", "/api/signing-key").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/warrants").hasRole("REQUESTER")
                .requestMatchers("/api/approvals/**").hasRole("APPROVER")
                .requestMatchers(HttpMethod.DELETE, "/api/warrants/**").hasRole("APPROVER")
                .requestMatchers(HttpMethod.POST, "/api/policies", "/api/subjects").hasAnyRole("REQUESTER", "APPROVER")
                .anyRequest().authenticated();
    }

    // Shared by both chains. The dashboard holds a session cookie, so CSRF stays on (token in the XSRF-TOKEN cookie,
    // echoed as X-XSRF-TOKEN). A request carrying Authorization (Basic, Bearer) has no cookie to forge, so it skips CSRF.
    // Unauthenticated API calls get a bare 401, never a challenge that would pop a browser dialog.
    private static HttpSecurity common(HttpSecurity http) throws Exception {
        HttpStatusEntryPoint unauthorized = new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED);
        CsrfTokenRequestAttributeHandler csrfHandler = new CsrfTokenRequestAttributeHandler();
        csrfHandler.setCsrfRequestAttributeName(null); // load the token on every request so the cookie is always set
        return http
                .authorizeHttpRequests(SecurityConfig::rules)
                .exceptionHandling(e -> e.authenticationEntryPoint(unauthorized))
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        .csrfTokenRequestHandler(csrfHandler)
                        .ignoringRequestMatchers(req -> req.getHeader("Authorization") != null))
                .logout(logout -> logout
                        .logoutUrl("/api/auth/logout")
                        .logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler(HttpStatus.NO_CONTENT)));
    }

    // Called by Spring Security only with the dev profile: console login with the accounts in application-dev.yml,
    // curl with Basic. Every dev account has every role.
    @Bean
    @Order(0)
    @Profile("dev")
    SecurityFilterChain devApi(HttpSecurity http) throws Exception {
        common(http.securityMatcher("/api/**"))
                .httpBasic(basic -> basic.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)));
        return http.build();
    }

    @Bean
    @Profile("dev")
    UserDetailsService devUsers(DevAccounts accounts) {
        return new InMemoryUserDetailsManager(accounts.accounts().stream()
                .map(a -> User.withUsername(a.email()).password(a.password()).roles("REQUESTER", "APPROVER", "AUDITOR").build())
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

    // Called by Spring Security only with the oidc profile. The console logs in at Keycloak (code flow + PKCE) and
    // comes back with a session; curl and scripts send a Keycloak access token. Groups become roles (KeycloakGroups).
    // After login the browser goes back to "/", which is the dashboard when it comes through the dashboard's proxy.
    @Bean
    @Order(0)
    @Profile("oidc")
    SecurityFilterChain oidcApi(HttpSecurity http) throws Exception {
        KeycloakGroups groups = new KeycloakGroups();
        JwtAuthenticationConverter bearer = new JwtAuthenticationConverter();
        bearer.setJwtGrantedAuthoritiesConverter(groups.forJwt());
        common(http.securityMatcher("/api/**", "/oauth2/**", "/login/oauth2/**"))
                .oauth2Login(login -> login
                        .userInfoEndpoint(u -> u.userAuthoritiesMapper(groups.forLogin()))
                        .defaultSuccessUrl("/", true))
                .oauth2ResourceServer(rs -> rs.jwt(j -> j.jwtAuthenticationConverter(bearer)));
        return http.build();
    }

    // Built from the issuer by Keycloak's URL layout, so nothing is fetched at startup. PKCE on.
    @Bean
    @Profile("oidc")
    ClientRegistrationRepository keycloakClient(OidcSettings oidc) {
        return new InMemoryClientRegistrationRepository(ClientRegistration.withRegistrationId("keycloak")
                .clientId(oidc.clientId())
                .clientSecret(oidc.clientSecret())
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .scope("openid", "profile", "email")
                .issuerUri(oidc.issuer())
                .authorizationUri(oidc.endpoint("auth"))
                .tokenUri(oidc.endpoint("token"))
                .jwkSetUri(oidc.endpoint("certs"))
                .userInfoUri(oidc.endpoint("userinfo"))
                .userNameAttributeName(IdTokenClaimNames.SUB)
                .clientName("Keycloak")
                .clientSettings(ClientRegistration.ClientSettings.builder().requireProofKey(true).build())
                .build());
    }

    // Bearer tokens: keys are fetched lazily on the first token; iss must be our realm.
    @Bean
    @Profile("oidc")
    JwtDecoder keycloakTokens(OidcSettings oidc) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(oidc.endpoint("certs")).build();
        decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(oidc.issuer()));
        return decoder;
    }
}
