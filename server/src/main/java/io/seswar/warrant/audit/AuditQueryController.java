package io.seswar.warrant.audit;

import io.seswar.warrant.audit.EventGap;
import io.seswar.warrant.audit.UnwarrantedSession;
import io.seswar.warrant.node.Node;
import io.seswar.warrant.audit.EventGapRepository;
import io.seswar.warrant.node.NodeRepository;
import io.seswar.warrant.audit.UnwarrantedSessionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * 감사 조회. 지금은 목록 두 개뿐이다 — 기간 · 노드 필터와 페이지는 아직 없다.
 * 커널 판정 레코드(audit_event)는 노드가 아직 올리지 않아 조회할 것이 없다.
 */
@RestController
@RequestMapping("/api/audit")
@RequiredArgsConstructor
public class AuditQueryController {

    private final UnwarrantedSessionRepository unwarranted;
    private final EventGapRepository gaps;
    private final NodeRepository nodes;

    public record UnwarrantedView(UUID id, String node, Instant observedAt, String loginAccount,
                                  String sshKeyFingerprint, String sourceAddress, long cgroupId, String reason) {
    }

    public record GapView(UUID id, String node, Instant from, Instant to, Long droppedCount, String cause) {
    }

    /** 영장 없이 성립한 세션 (§07 STEP 2). */
    @GetMapping("/unwarranted")
    public List<UnwarrantedView> unwarranted() {
        Map<UUID, String> host = hostnames();
        return unwarranted.findAllByOrderByObservedAtDesc().stream()
                .map((UnwarrantedSession u) -> new UnwarrantedView(u.getId(), host.get(u.getNodeId()), u.getObservedAt(),
                        u.getLoginAccount(), u.getSshKeyFingerprint(), u.getSourceAddress(), u.getCgroupId(), u.getReason()))
                .toList();
    }

    /** 유실 구간. 숨기지 않는다 — 이벤트와 같은 화면에 겹쳐 보여야 한다. */
    @GetMapping("/gaps")
    public List<GapView> gaps() {
        Map<UUID, String> host = hostnames();
        return gaps.findAllByOrderByFromDesc().stream()
                .map((EventGap g) -> new GapView(g.getId(), host.get(g.getNodeId()), g.getFrom(), g.getTo(),
                        g.getDroppedCount(), g.getCause()))
                .toList();
    }

    private Map<UUID, String> hostnames() {
        return nodes.findAll().stream().collect(Collectors.toMap(Node::getId, Node::getHostname));
    }
}
