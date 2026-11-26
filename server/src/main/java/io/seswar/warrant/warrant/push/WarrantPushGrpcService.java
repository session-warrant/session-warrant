package io.seswar.warrant.warrant.push;

import io.grpc.Status;
import io.grpc.stub.ServerCallStreamObserver;
import io.grpc.stub.StreamObserver;
import io.seswar.warrant.node.NodePeer;
import io.seswar.warrant.proto.AgentProtos.ExtensionAck;
import io.seswar.warrant.proto.AgentProtos.ExtensionRequest;
import io.seswar.warrant.warrant.WarrantExtensionService;
import io.seswar.warrant.proto.AgentProtos.HeartbeatRequest;
import io.seswar.warrant.proto.AgentProtos.HeartbeatResponse;
import io.seswar.warrant.proto.AgentProtos.LookupRequest;
import io.seswar.warrant.proto.AgentProtos.LookupResponse;
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
    private final WarrantExtensionService extensions;

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

    @Override
    public void heartbeat(HeartbeatRequest req, StreamObserver<HeartbeatResponse> out) {
        String host = req.getNode().getHostname();
        String identity = identify(host, out);
        if (identity == null) {
            return;
        }
        int expected = push.heartbeat(identity, host);
        if (expected != req.getActiveWarrants()) {
            log.info("node {} holds {} active warrants, the server has {}: it should resubscribe",
                    host, req.getActiveWarrants(), expected);
        }
        out.onNext(HeartbeatResponse.newBuilder().setExpectedActiveWarrants(expected).build());
        out.onCompleted();
    }

    @Override
    public void lookupActiveWarrant(LookupRequest req, StreamObserver<LookupResponse> out) {
        if (identify(req.getHostname(), out) == null) {
            return;
        }
        out.onNext(LookupResponse.newBuilder()
                .addAllWarrants(push.lookup(req.getHostname(), req.getLoginAccount(), req.getSshKeyFingerprint()))
                .build());
        out.onCompleted();
    }

    /**
     * warrantd 의 T-5분 연장 요청. 결과는 즉답(접수 · 자동 승인 · 중복 · 상한 · 거부)이고, 연장 자체는 새 revision
     * push 로 간다 — 자동 승인이면 여기서 바로, 사람 승인이면 승인할 때. 인증서가 있으면 그 노드가 대상 호스트여야 한다.
     */
    @Override
    public void requestExtension(ExtensionRequest req, StreamObserver<ExtensionAck> out) {
        NodePeer peer = NodePeer.current();
        WarrantExtensionService.Result r = extensions.requestAutomatically(req.getWarrantId(),
                peer == null ? null : peer.hostname(), req.getDetectedWorkload(),
                java.time.Duration.ofNanos(req.getRequestedExtensionNs()));
        if (r.warrant() != null) {
            push.push(r.warrant()); // after the commit: requestAutomatically is its own transaction
        }
        log.info("extension request for warrant {}: {} ({})", req.getWarrantId(), r.outcome(), r.message());
        out.onNext(ExtensionAck.newBuilder()
                .setOutcome(ExtensionAck.Outcome.valueOf("OUTCOME_" + r.outcome().name()))
                .setMessage(r.message())
                .build());
        out.onCompleted();
    }

    // Same rule as subscribe and the audit stream: with a certificate the node is that certificate and must use its
    // name; in plaintext (local development) it is its reported hostname. Answers the call with an error and
    // returns null when the caller may not speak for that host.
    private static String identify(String host, StreamObserver<?> out) {
        if (host.isBlank()) {
            out.onError(Status.INVALID_ARGUMENT.withDescription("hostname is empty").asRuntimeException());
            return null;
        }
        NodePeer peer = NodePeer.current();
        if (peer == null) {
            return "dev:" + host;
        }
        if (!host.equals(peer.hostname())) {
            out.onError(Status.PERMISSION_DENIED
                    .withDescription("certificate is for " + peer.hostname() + ", request says " + host).asRuntimeException());
            return null;
        }
        return peer.identity();
    }
}
