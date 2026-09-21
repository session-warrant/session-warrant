package io.seswar.warrant.config;

/**
 * <b>자체 회원가입을 만들지 않는다.</b> 조직 신원 매핑이 제품 핵심이므로
 * OIDC 공급자(Keycloak)를 붙이고, {@code sub} 가 그대로 {@code subject_id} 의 출처가 된다(기술 스택 §06).
 * 여기에 로컬 계정을 만드는 순간 "누가"의 신뢰도가 그 계정 수준으로 떨어진다.
 */
// @Configuration @EnableWebSecurity
public class SecurityConfig {

    // /api/**    → OIDC 인증 필요
    // /slack/**  → 인증 제외. 대신 Slack 서명 검증이 필수다 (SlackInteractionController 주석 참조)
    // /actuator/health → 공개, 나머지 actuator 는 보호
    //
    // 권한 분리:
    //   REQUESTER  영장 요청
    //   APPROVER   승인 · 연장 · 회수
    //   AUDITOR    감사 조회 전용 — 발급 권한 없음. 감사자가 발급할 수 있으면 감사가 아니다
    //   OPERATOR   노드 · 정책 관리
}
