package io.seswar.warrant.node;

import io.seswar.warrant.node.Node;
import io.seswar.warrant.node.NodeRepository;
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

    public record NodeView(UUID id, String hostname, String kernelVersion, boolean bpfLsmEnabled,
                           String agentVersion, Instant lastSeenAt) {
        static NodeView of(Node n) {
            return new NodeView(n.getId(), n.getHostname(), n.getKernelVersion(), n.isBpfLsmEnabled(),
                    n.getAgentVersion(), n.getLastSeenAt());
        }
    }

    @GetMapping
    public List<NodeView> list() {
        return nodes.findAll().stream().map(NodeView::of)
                .sorted(Comparator.comparing(NodeView::hostname)).toList();
    }
}
