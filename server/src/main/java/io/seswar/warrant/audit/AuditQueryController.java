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
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.data.domain.Limit;
import io.seswar.warrant.proto.AuditProtos.Hook;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * 감사 조회. 커널 판정 기록 · 무영장 세션 · 유실 구간. 노드 필터와 페이지는 아직 없다.
 */
@RestController
@RequestMapping("/api/audit")
@RequiredArgsConstructor
public class AuditQueryController {

    private final UnwarrantedSessionRepository unwarranted;
    private final EventGapRepository gaps;
    private final NodeRepository nodes;
    private final AuditEventRepository events;

    static final int MAX_EVENTS = 5000;

    public record EventView(UUID id, String node, Instant occurredAt, AuditEventType type, String hook, Verdict verdict,
                            String mode, String origin, String tagSource, long warrantId, Integer kernelSubjectId,
                            Long pid, Integer uid, Long cgroupId, String comm, Long deviceId, Long inode,
                            String resolvedPath, String destination) {
    }

    /** 커널 판정 기록. 기본은 최근 24시간, 최신 순. */
    @GetMapping("/events")
    public List<EventView> events(@RequestParam(required = false) Instant since,
                                  @RequestParam(defaultValue = "1000") int limit) {
        Instant from = since != null ? since : Instant.now().minus(Duration.ofHours(24));
        Map<UUID, String> host = hostnames();
        return events.findByOccurredAtGreaterThanEqualOrderByOccurredAtDesc(from, Limit.of(Math.clamp(limit, 1, MAX_EVENTS)))
                .stream()
                .map(e -> new EventView(e.getId(), host.get(e.getNodeId()), e.getOccurredAt(), e.getType(), hookName(e.getHook()),
                        e.getVerdict(), e.getMode() == null ? null : e.getMode().name(), e.getOrigin().name(),
                        e.getTagSource().name(), e.getWarrantId(), e.getKernelSubjectId(), e.getPid(), e.getUid(),
                        e.getCgroupId(), e.getComm(), e.getDeviceId(), e.getInode(), e.getResolvedPath(), e.getDestination()))
                .toList();
    }

    // Rows stored before V3 have no hook.
    private static String hookName(Short hook) {
        if (hook == null) {
            return null;
        }
        Hook h = Hook.forNumber(hook);
        return h == null ? String.valueOf(hook) : h.name();
    }

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
