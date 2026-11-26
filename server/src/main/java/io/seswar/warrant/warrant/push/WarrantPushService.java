package io.seswar.warrant.warrant.push;

import io.seswar.warrant.node.NodeRepository;
import io.seswar.warrant.warrant.api.WarrantController;
import io.seswar.warrant.warrant.store.Warrant;
import io.seswar.warrant.warrant.store.WarrantRepository;
import com.google.protobuf.ByteString;
import io.seswar.warrant.proto.AgentProtos.PushMessage;
import io.seswar.warrant.proto.AgentProtos.ResyncComplete;
import io.seswar.warrant.proto.WarrantProtos.SignedWarrant;
import io.seswar.warrant.warrant.store.WarrantRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * 영장을 노드로 내려보낸다. 발급 · 취소가 전부 이 경로를 쓴다. 노드의 생존 신호와 캐시가 빈 노드의 조회도 받는다.
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
    private final NodeRepository nodes;
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

    /**
     * 노드 생존 신호. 노드의 마지막 소식 시각을 갱신하고, 그 노드가 들고 있어야 할 활성 영장 수를 돌려준다 —
     * 노드는 자기 커널 맵의 수와 다르면 push 를 놓친 것으로 보고 다시 구독한다.
     * 감사 스트림에 한 번도 안 붙은 노드는 여기서 만들지 않는다(노드 등록은 감사 스트림의 일이다).
     */
    @Transactional
    public int heartbeat(String identity, String hostname) {
        Instant now = clock.instant();
        nodes.findByClientCertFingerprint(identity).ifPresent(n -> n.touch(now));
        return warrants.findActiveForHost(hostname, now).size();
    }

    /**
     * 노드 캐시가 비었을 때의 조회. 그 노드 · 그 계정 · 그 키 지문이 셋 다 맞는 활성 영장만 돌려준다.
     * 지문이나 계정이 비면 빈 응답이다 — 비어 있는 값은 와일드카드가 아니다.
     */
    @Transactional(readOnly = true)
    public List<SignedWarrant> lookup(String hostname, String loginAccount, String fingerprint) {
        if (loginAccount.isBlank() || fingerprint.isBlank()) {
            return List.of();
        }
        return warrants.findActiveForHost(hostname, clock.instant()).stream()
                .filter(w -> w.getLoginAccount().equals(loginAccount) && w.getSshKeyFingerprints().contains(fingerprint))
                .map(WarrantPushService::envelope)
                .toList();
    }

    private static PushMessage message(Warrant w) {
        return PushMessage.newBuilder().setWarrant(envelope(w)).build();
    }

    // The stored signed bytes go out as they are; re-serializing would break the signature.
    private static SignedWarrant envelope(Warrant w) {
        return SignedWarrant.newBuilder()
                .setWarrant(ByteString.copyFrom(w.getSignedPayload()))
                .setSignature(ByteString.copyFrom(w.getSignature()))
                .setKeyId(w.getSigningKeyId())
                .build();
    }
}
