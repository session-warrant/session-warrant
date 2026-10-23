package io.seswar.warrant.application;

import io.seswar.warrant.domain.node.Node;
import io.seswar.warrant.repository.NodeRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
/** 노드 등록 · 관리. 최신화 */
@Slf4j
@Service
@RequiredArgsConstructor
public class NodeRegistry {

    private final NodeRepository nodes;
    private final Clock clock;

    /** NodeHello 를 proto 없이 옮긴 것과, 그 스트림의 seq_epoch. */
    public record Report(String hostname, String kernelVersion, boolean bpfLsmEnabled, String agentVersion,
                         Set<String> attachedHooks, Instant bootedAt, long seqEpoch) {
    }

    /** created: 처음 본 노드. epochChanged: 이미 알던 노드인데 seq_epoch 가 바뀌었다(조사 대상). */
    public record Registration(UUID nodeId, boolean created, boolean epochChanged) {
    }

    /**노드 탐색 및 생성 */
    @Transactional
    public Registration register(String identity, Report report) {
        Instant now = clock.instant();
        Optional<Node> found = nodes.findByClientCertFingerprint(identity);

        if (found.isEmpty()) {
            Node created = nodes.saveAndFlush(Node.builder()
                    .clientCertFingerprint(identity)
                    .hostname(report.hostname())
                    .kernelVersion(report.kernelVersion())
                    .bpfLsmEnabled(report.bpfLsmEnabled())
                    .agentVersion(report.agentVersion())
                    .attachedHooks(Set.copyOf(report.attachedHooks()))
                    .bootedAt(report.bootedAt())
                    .currentSeqEpoch(report.seqEpoch())
                    .lastSeenAt(now)
                    .build());
            return new Registration(created.getId(), true, false);
        }

        Node node = found.get();
        boolean epochChanged = !Objects.equals(node.getCurrentSeqEpoch(), report.seqEpoch());
        if (epochChanged) {
            log.warn("node {} seq_epoch changed {} -> {} (local store was reset)",
                    node.getId(), node.getCurrentSeqEpoch(), report.seqEpoch());
        }
        node.refresh(report.hostname(), report.kernelVersion(), report.bpfLsmEnabled(), report.agentVersion(),
                report.attachedHooks(), report.bootedAt(), report.seqEpoch(), now);
        nodes.saveAndFlush(node);
        return new Registration(node.getId(), false, epochChanged);
    }

    /** 노드 생존 표시*/
    @Transactional
    public void heartbeat(UUID nodeId) {
        nodes.findById(nodeId)
                .orElseThrow(() -> new IllegalArgumentException("unknown node " + nodeId))
                .touch(clock.instant());
    }

    /** 일정 시간 소식이 없는 노드*/
    @Transactional(readOnly = true)
    public List<UUID> staleNodes(Duration threshold) {
        return nodes.findByLastSeenAtBefore(clock.instant().minus(threshold)).stream()
                .map(Node::getId)
                .toList();
    }
}
