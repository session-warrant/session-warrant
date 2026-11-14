package io.seswar.warrant.warrant.push;

import io.grpc.Status;
import io.grpc.stub.ServerCallStreamObserver;
import io.grpc.stub.StreamObserver;
import io.seswar.warrant.node.NodePeer;
import io.seswar.warrant.warrant.push.WarrantPushService;
import io.seswar.warrant.proto.AgentProtos.PushMessage;
import io.seswar.warrant.proto.AgentProtos.SubscribeRequest;
import io.seswar.warrant.proto.WarrantPushServiceGrpc;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * warrantd ← 중앙. <b>서버 스트리밍</b>. 구독하면 그 노드의 활성 영장 전부 → ResyncComplete 를 보내고,
 * 스트림을 열어 둔 채 발급 · 취소가 생길 때마다 밀어 넣는다.
 *
 * <p>단절 시 재연결은 warrantd 의 백오프에 맡긴다. 서버가 재연결을 유도하려 들지 말 것.
 * mTLS 면 노드는 인증서 이름(CN)으로만 구독할 수 있다 — 남의 이름으로 구독하면 그 노드의 정책이 보인다.
 * 평문(로컬 개발)이면 노드가 신고한 hostname 을 그대로 믿는다.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class WarrantPushGrpcService extends WarrantPushServiceGrpc.WarrantPushServiceImplBase {

    private final WarrantPushService push;
    private final NodeStreamRegistry streams;

    @Override
    public void subscribe(SubscribeRequest req, StreamObserver<PushMessage> out) {
        String host = req.getNode().getHostname();
        if (host.isBlank()) {
            out.onError(Status.INVALID_ARGUMENT.withDescription("NodeHello.hostname is empty").asRuntimeException());
            return;
        }
        NodePeer peer = NodePeer.current();
        if (peer != null && !host.equals(peer.hostname())) {
            out.onError(Status.PERMISSION_DENIED
                    .withDescription("certificate is for " + peer.hostname() + ", NodeHello says " + host).asRuntimeException());
            return;
        }
        // Attach before reading the active set, so a warrant issued in between is not missed.
        streams.attach(host, out);
        ((ServerCallStreamObserver<PushMessage>) out).setOnCancelHandler(() -> streams.detach(host, out));

        List<PushMessage> initial = push.activeSet(host);
        synchronized (out) {
            initial.forEach(out::onNext);
        }
        log.info("node {} subscribed: {} active warrants", host, initial.size() - 1);
    }
}
