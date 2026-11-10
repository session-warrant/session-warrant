package io.seswar.warrant.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.grpc.server.GlobalServerInterceptor;
import org.springframework.grpc.server.security.AuthenticationProcessInterceptor;
import org.springframework.grpc.server.security.GrpcSecurity;

/**
 * 노드 ↔ 중앙 gRPC 의 인증. <b>사람 로그인(OIDC)과 섞지 않는다.</b> 노드 신원은 mTLS 인증서로 간다(아직 없다 —
 * 그 전까지 노드는 NodeHello 의 hostname 으로 식별된다). 영장 스트림에는 정책 전체가 흐르므로 mTLS 가
 * 붙으면 여기서 인증서 없는 호출을 거부한다.
 *
 * <p>남은 것: 서버 포트 · TLS, keepalive(지금은 application.yml), 최대 메시지 크기.
 */
@Configuration
public class GrpcConfig {

    // Called by Spring gRPC for every server. Without it, the oidc profile's JwtDecoder makes Spring gRPC demand a
    // Bearer token on node calls, and every warrantd stream ends UNAUTHENTICATED (2026-11-09).
    @Bean
    @GlobalServerInterceptor
    AuthenticationProcessInterceptor nodeCalls(GrpcSecurity grpc) throws Exception {
        return grpc.authorizeRequests(r -> r.allRequests().permitAll()).build();
    }
}
