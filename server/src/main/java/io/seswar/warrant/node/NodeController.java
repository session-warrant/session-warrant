package io.seswar.warrant.node;

import io.seswar.warrant.identity.CurrentSubject;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;

/**
 * 노드 목록. 감사 스트림으로 한 번이라도 붙은 노드만 있다.
 * {@code bpfLsmEnabled=false} 노드에는 ENFORCE 영장을 발급해도 강제되지 않는다 — 화면이 이걸 드러내야 한다.
 */
@RestController
@RequestMapping("/api/nodes")
@RequiredArgsConstructor
public class NodeController {

    private final NodeRepository nodes;
    private final NodeRevocationService revocation;
    private final NodeConnections connections;
    private final CurrentSubject current;

    /** {@code revokedAt} 이 있으면 폐기된 노드다 — 그 신원으로는 붙지 못한다. */
    public record NodeView(UUID id, String hostname, String kernelVersion, boolean bpfLsmEnabled,
                           String agentVersion, Instant lastSeenAt, Instant revokedAt, String revokeReason) {
        static NodeView of(Node n) {
            return new NodeView(n.getId(), n.getHostname(), n.getKernelVersion(), n.isBpfLsmEnabled(),
                    n.getAgentVersion(), n.getLastSeenAt(), n.getRevokedAt(), n.getRevokeReason());
        }
    }

    public record Revoke(String reason) {
    }

    @GetMapping
    public List<NodeView> list() {
        return nodes.findAll().stream().map(NodeView::of)
                .sorted(Comparator.comparing(NodeView::hostname)).toList();
    }

    /**
     * 노드 폐기(인증서 유출 · 노드 반납). 사유 필수, 되돌리지 않는다. 커밋 뒤 그 노드의 열린 감사 · 구독 스트림을 끊는다.
     * 이미 폐기됐으면 409.
     */
    @PostMapping("/{id}/revoke")
    public NodeView revoke(@PathVariable UUID id, @RequestBody Revoke body, Authentication auth) {
        Node n = revocation.revoke(id, current.require(auth).getId(), body.reason());
        connections.closeAll(n.getClientCertFingerprint(), "node revoked: " + n.getRevokeReason());
        return NodeView.of(n);
    }
}
