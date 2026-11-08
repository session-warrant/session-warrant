package io.seswar.warrant.application;

import com.google.protobuf.ByteString;
import io.seswar.warrant.domain.warrant.Warrant;
import io.seswar.warrant.grpc.NodeStreamRegistry;
import io.seswar.warrant.proto.AgentProtos.PushMessage;
import io.seswar.warrant.proto.AgentProtos.ResyncComplete;
import io.seswar.warrant.proto.WarrantProtos.SignedWarrant;
import io.seswar.warrant.repository.WarrantRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.util.ArrayList;
import java.util.List;

/**
 * 영장을 노드로 내려보낸다. 발급 · 취소가 전부 이 경로를 쓴다.
 *
 * <p>push 실패는 <b>새 정보가 늦게 도착하는</b> 문제일 뿐 집행이 멈추는 문제가 아니다(§17).
 * 단 하나 예외가 취소다 — 취소 push 실패는 권한이 살아 있다는 뜻이다. 지금은 로그만 남긴다.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class WarrantPushService {

    private final NodeStreamRegistry streams;
    private final WarrantRepository warrants;
    private final Clock clock;

    // Called by WarrantController after the issue or revoke transaction committed.
    public void push(Warrant w) {
        PushMessage m = message(w);
        for (String host : w.getTargetHosts()) {
            int n = streams.send(host, m);
            if (n == 0) {
                log.info("warrant {} rev {}: {} is not connected, it catches up on its next subscribe",
                        w.getWarrantId(), w.getRevision(), host);
            }
        }
    }

    /** 노드가 구독하면 처음 받는 것 — 그 노드의 활성 영장 전부, 그리고 ResyncComplete. */
    @Transactional(readOnly = true)
    public List<PushMessage> activeSet(String hostname) {
        List<PushMessage> out = new ArrayList<>();
        for (Warrant w : warrants.findActiveForHost(hostname, clock.instant())) {
            out.add(message(w));
        }
        out.add(PushMessage.newBuilder()
                .setResyncComplete(ResyncComplete.newBuilder().setActiveCount(out.size()))
                .build());
        return out;
    }

    // The stored signed bytes go out as they are; re-serializing would break the signature.
    private static PushMessage message(Warrant w) {
        return PushMessage.newBuilder().setWarrant(SignedWarrant.newBuilder()
                        .setWarrant(ByteString.copyFrom(w.getSignedPayload()))
                        .setSignature(ByteString.copyFrom(w.getSignature()))
                        .setKeyId(w.getSigningKeyId()))
                .build();
    }
}
