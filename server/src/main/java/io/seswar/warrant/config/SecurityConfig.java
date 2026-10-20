package io.seswar.warrant.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * <b>자체 회원가입을 만들지 않는다.</b> 조직 신원 매핑이 제품 핵심이므로
 * OIDC 공급자(Keycloak)를 붙이고, {@code sub} 가 그대로 {@code subject_id} 의 출처가 된다(기술 스택 §06).
 * 여기에 로컬 계정을 만드는 순간 "누가"의 신뢰도가 그 계정 수준으로 떨어진다.
 */
@Configuration
@EnableWebSecurity
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
