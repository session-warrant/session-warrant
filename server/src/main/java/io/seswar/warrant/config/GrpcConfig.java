package io.seswar.warrant.config;

import io.grpc.Contexts;
import io.grpc.Grpc;
import io.grpc.Metadata;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.Status;
import io.seswar.warrant.node.NodePeer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.grpc.server.GlobalServerInterceptor;
import org.springframework.grpc.server.security.AuthenticationProcessInterceptor;
import org.springframework.grpc.server.security.GrpcSecurity;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

/**
 * 노드 ↔ 중앙 gRPC 의 인증. <b>사람 로그인(OIDC)과 섞지 않는다.</b> 노드 신원은 mTLS 클라이언트 인증서다.
 *
 * <p>{@code mtls} 프로필이 TLS 를 켜고 클라이언트 인증서를 필수로 한다(application-mtls.yml) — 사내 CA 가 서명하지 않은
 * 인증서는 핸드셰이크에서 끊긴다. 여기서는 그 인증서를 {@link NodePeer} 로 호출에 싣고, 노드가 말하는 호스트 이름이
 * 인증서와 같은지는 각 서비스가 본다. 프로필 없이 띄우면 평문이고 노드는 호스트 이름으로 식별된다(로컬 개발 전용).
 *
 * <p>남은 것: 인증서 폐기(CRL), keepalive(지금은 application.yml), 최대 메시지 크기.
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

    /**
     * Called by gRPC on every node call. Puts the client certificate on the call as {@link NodePeer}.
     * With {@code warrant.node-tls.required} a call without one is refused even if TLS were misconfigured to let it in.
     */
    @Bean
    @GlobalServerInterceptor
    ServerInterceptor nodeCertificate(@Value("${warrant.node-tls.required:false}") boolean required) {
        return new ServerInterceptor() {
            @Override
            public <Q, R> ServerCall.Listener<Q> interceptCall(ServerCall<Q, R> call, Metadata headers, ServerCallHandler<Q, R> next) {
                NodePeer peer = peerOf(call.getAttributes().get(Grpc.TRANSPORT_ATTR_SSL_SESSION));
                if (peer == null) {
                    if (required) {
                        call.close(Status.UNAUTHENTICATED.withDescription("node certificate required"), new Metadata());
                        return new ServerCall.Listener<>() { };
                    }
                    return next.startCall(call, headers);
                }
                return Contexts.interceptCall(peer.attach(io.grpc.Context.current()), call, headers, next);
            }
        };
    }

    private static NodePeer peerOf(SSLSession session) {
        if (session == null) {
            return null;
        }
        try {
            Certificate[] chain = session.getPeerCertificates();
            return chain.length > 0 && chain[0] instanceof X509Certificate leaf ? NodePeer.of(leaf) : null;
        } catch (SSLPeerUnverifiedException e) {
            return null;
        }
    }
}
