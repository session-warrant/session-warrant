package io.seswar.warrant.grpc;

/**
 * warrantd ← 중앙. <b>서버 스트리밍</b>.
 *
 * <p>생성 코드가 붙으면 {@code WarrantPushServiceGrpc.WarrantPushServiceImplBase} 를 상속한다.
 * 지금은 proto 가 확정되기 전이므로 시그니처만 둔다.
 *
 * <h3>스트림 수명</h3>
 * 단절 시 재연결은 warrantd 쪽 {@code grpc.WithConnectParams} 백오프에 맡긴다.
 * 서버가 재연결을 유도하려 들지 말 것 — 노드가 알아서 붙는다.
 */
// @Service  // extends WarrantPushServiceGrpc.WarrantPushServiceImplBase
public class WarrantPushGrpcService {

    /**
     * 노드가 스트림을 연다. 서버는 이 스트림으로 발급 · 연장 · 취소를 밀어 넣는다.
     */
    // public void subscribe(SubscribeRequest req, StreamObserver<WarrantProto> out)
    public void subscribe(/* SubscribeRequest req, StreamObserver<WarrantProto> out */) {
        // 1. 노드 인증 (mTLS 또는 노드 토큰). 아무나 영장 스트림을 열면 정책 전체가 유출된다
        // 2. NodeRegistry.register() / heartbeat
        // 3. WarrantPushService.resync(nodeId) — 현재 활성 집합 전체를 먼저 내려준다
        // 4. 스트림을 NodeStreamRegistry 에 등록하고 종료까지 유지
        throw new UnsupportedOperationException("미구현");
    }

    /**
     * warrantd 캐시가 비었을 때의 <b>선택적</b> 조회 경로. PAM 질의에 답하는 것은 warrantd 다 —
     * 중앙이 인증 경로에 끼면 중앙 장애가 곧 로그인 장애가 된다. 타임아웃 시 노드는 fail-open 한다.
     */
    // public void lookupActiveWarrant(LookupRequest req, StreamObserver<LookupResponse> out)
    public void lookupActiveWarrant() {
        throw new UnsupportedOperationException("미구현");
    }
}
