package io.seswar.warrant.node;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.util.UUID;

/**
 * 노드 폐기 — 인증서 폐기 목록(CRL)의 작은 대역. 노드 인증서를 믿는 곳이 이 서버 하나뿐이라 서버가 그 지문을 거부하면 같은 효과다.
 * 발급 스크립트 · TLS 설정은 그대로 두고, gRPC 호출마다 신원이 폐기됐는지 본다(GrpcConfig · 각 gRPC 서비스).
 *
 * <p>되돌리지 않는다. 다시 붙이려면 새 인증서를 발급한다 — 새 지문은 새 노드 행이 된다.
 * 노드에 걸린 영장은 회수하지 않는다(영장은 호스트 이름을 가리킨다). 필요하면 따로 회수한다.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class NodeRevocationService {

    private final NodeRepository nodes;
    private final Clock clock;

    /** 폐기. 열린 스트림은 호출자가 커밋 뒤에 {@link NodeConnections#closeAll} 로 끊는다. */
    @Transactional
    public Node revoke(UUID nodeId, UUID by, String reason) {
        if (reason == null || reason.isBlank()) {
            throw new IllegalArgumentException("revoking a node needs a reason");
        }
        Node n = nodes.findById(nodeId).orElseThrow(() -> new IllegalArgumentException("unknown node " + nodeId));
        n.revoke(clock.instant(), by, reason.strip());
        log.warn("node {} ({}) revoked: {}", n.getHostname(), n.getClientCertFingerprint(), n.getRevokeReason());
        return n;
    }

    // Called on every node gRPC call (GrpcConfig for certificates, the services for plaintext identities).
    @Transactional(readOnly = true)
    public boolean isRevoked(String identity) {
        return nodes.existsByClientCertFingerprintAndRevokedAtIsNotNull(identity);
    }

    public void requireActive(String identity) {
        if (isRevoked(identity)) {
            throw new NodeRevokedException(identity);
        }
    }
}
