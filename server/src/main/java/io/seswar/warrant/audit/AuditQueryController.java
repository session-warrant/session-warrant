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
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * 감사 조회. 커널 판정 기록 · 무영장 세션 · 유실 구간. 노드 필터는 아직 없다.
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
    /** 이어 받을 시작점. 다음 요청의 {@code after} 로 그대로 돌려보낸다. */
    static final String CURSOR = "X-Audit-Cursor";

    public record EventView(UUID id, long seq, String node, Instant occurredAt, AuditEventType type, String hook,
                            Verdict verdict, String mode, String origin, String tagSource, long warrantId,
                            Integer kernelSubjectId, Long pid, Integer uid, Long cgroupId, String comm, Long deviceId,
                            Long inode, String resolvedPath, String destination) {
    }

    /**
     * 커널 판정 기록. 두 가지로 부른다.
     * <ul>
     *   <li>{@code after} 없음 — 처음 화면. {@code since}(기본 최근 24시간) 이후, 발생 시각 최신 순.</li>
     *   <li>{@code after=N} — 이어 받기. 수신 순번 N 뒤에 <b>서버가 받은</b> 것, 받은 순. 발생 시각은 과거일 수 있다.</li>
     * </ul>
     * 어느 쪽이든 {@value #CURSOR} 헤더가 다음 {@code after} 다. 한 스냅숏에서 읽어야 목록과 커서 사이에
     * 끼어든 기록이 없다 — 그래서 REPEATABLE READ.
     */
    @GetMapping("/events")
    @Transactional(readOnly = true, isolation = Isolation.REPEATABLE_READ)
    public ResponseEntity<List<EventView>> events(@RequestParam(required = false) Instant since,
                                                  @RequestParam(required = false) Long after,
                                                  @RequestParam(defaultValue = "1000") int limit) {
        Limit max = Limit.of(Math.clamp(limit, 1, MAX_EVENTS));
        long cursor = events.maxReceivedSeq();
        List<AuditEvent> rows;
        if (after == null) {
            Instant from = since != null ? since : Instant.now().minus(Duration.ofHours(24));
            rows = events.findByOccurredAtGreaterThanEqualOrderByOccurredAtDesc(from, max);
        } else {
            rows = events.findByReceivedSeqGreaterThanOrderByReceivedSeqAsc(after, max);
            // A full page means more may follow: continue from the last row, not from the newest.
            if (rows.size() == max.max()) {
                cursor = rows.getLast().getReceivedSeq();
            }
        }
        Map<UUID, String> host = hostnames();
        List<EventView> body = rows.stream()
                .map(e -> new EventView(e.getId(), e.getReceivedSeq(), host.get(e.getNodeId()), e.getOccurredAt(), e.getType(),
                        hookName(e.getHook()), e.getVerdict(), e.getMode() == null ? null : e.getMode().name(),
                        e.getOrigin().name(), e.getTagSource().name(), e.getWarrantId(), e.getKernelSubjectId(), e.getPid(),
                        e.getUid(), e.getCgroupId(), e.getComm(), e.getDeviceId(), e.getInode(), e.getResolvedPath(),
                        e.getDestination()))
                .toList();
        return ResponseEntity.ok().header(CURSOR, Long.toString(cursor)).body(body);
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
