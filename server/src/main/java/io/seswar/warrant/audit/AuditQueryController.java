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
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * 감사 조회. 커널 판정 기록 · 구간 집계 · 무영장 세션 · 유실 구간, 그리고 새 기록 알림.
 */
@RestController
@RequestMapping("/api/audit")
@RequiredArgsConstructor
public class AuditQueryController {

    private final UnwarrantedSessionRepository unwarranted;
    private final EventGapRepository gaps;
    private final NodeRepository nodes;
    private final AuditEventRepository events;
    private final AuditStream stream;
    private final AuditSummaryQuery summaries;

    static final int MAX_EVENTS = 5000;
    /** 이어 받을 시작점. 다음 요청의 {@code after} 로 그대로 돌려보낸다. */
    static final String CURSOR = "X-Audit-Cursor";

    public record EventView(UUID id, long seq, String node, Instant occurredAt, AuditEventType type, String hook,
                            Verdict verdict, String mode, String origin, String tagSource, long warrantId,
                            Integer kernelSubjectId, Long pid, Integer uid, Long cgroupId, String comm, Long deviceId,
                            Long inode, String resolvedPath, String destination) {
    }

    /** 구간 원본 조회에서 한도에 걸렸을 때, 그 기간 · 조건의 전체 건수. */
    static final String TOTAL = "X-Audit-Total";
    // Bucket count ceiling for /summary: the chart draws a few dozen; thousands means a wrong bucket size.
    static final int MAX_BUCKETS = 5000;
    // Default bucket origin: a Monday 00:00 UTC. The dashboard sends its own local midnight instead.
    static final Instant DEFAULT_ORIGIN = Instant.parse("2000-01-03T00:00:00Z");

    /**
     * 커널 판정 기록. 두 가지로 부른다.
     * <ul>
     *   <li>{@code after} 없음 — 처음 화면 · 구간. {@code since}(기본 최근 24시간) 부터 {@code until}(없으면 끝없음) 전까지,
     *       발생 시각 최신 순. {@value #TOTAL} 헤더가 한도 없이 센 건수다.</li>
     *   <li>{@code after=N} — 이어 받기. 수신 순번 N 뒤에 <b>서버가 받은</b> 것, 받은 순. 발생 시각은 과거일 수 있다.</li>
     * </ul>
     * {@code kind=verdict} 면 LSM 판정만 준다 — kprobe 미러 · fork 를 빼서 한도를 판정 기록에 쓴다. {@code node} 는 호스트 이름.
     * 어느 쪽이든 {@value #CURSOR} 헤더가 다음 {@code after} 다. 한 스냅숏에서 읽어야 목록과 커서 사이에
     * 끼어든 기록이 없다 — 그래서 REPEATABLE READ.
     */
    @GetMapping("/events")
    @Transactional(readOnly = true, isolation = Isolation.REPEATABLE_READ)
    public ResponseEntity<List<EventView>> events(@RequestParam(required = false) Instant since,
                                                  @RequestParam(required = false) Instant until,
                                                  @RequestParam(required = false) Long after,
                                                  @RequestParam(required = false) String kind,
                                                  @RequestParam(required = false) String node,
                                                  @RequestParam(defaultValue = "1000") int limit) {
        int max = Math.clamp(limit, 1, MAX_EVENTS);
        long cursor = events.maxReceivedSeq();
        Specification<AuditEvent> where = matching(kind, nodeIds(node));
        List<AuditEvent> rows;
        ResponseEntity.BodyBuilder res = ResponseEntity.ok();
        if (after == null) {
            Instant from = since != null ? since : Instant.now().minus(Duration.ofHours(24));
            Specification<AuditEvent> range = where.and((e, q, cb) -> cb.greaterThanOrEqualTo(e.get("occurredAt"), from));
            if (until != null) {
                range = range.and((e, q, cb) -> cb.lessThan(e.get("occurredAt"), until));
            }
            Specification<AuditEvent> r = range;
            rows = events.findBy(r, q -> q.sortBy(Sort.by(Sort.Direction.DESC, "occurredAt")).limit(max).all());
            res.header(TOTAL, Long.toString(rows.size() < max ? rows.size() : events.count(r)));
        } else {
            Specification<AuditEvent> r = where.and((e, q, cb) -> cb.greaterThan(e.get("receivedSeq"), after));
            rows = events.findBy(r, q -> q.sortBy(Sort.by("receivedSeq")).limit(max).all());
            // A full page means more may follow: continue from the last row, not from the newest.
            if (rows.size() == max) {
                cursor = rows.getLast().getReceivedSeq();
            }
        }
        Map<UUID, String> host = hostnames();
        List<EventView> body = rows.stream()
                .map(e -> new EventView(e.getId(), e.getReceivedSeq(), host.get(e.getNodeId()), e.getOccurredAt(), e.getType(),
                        AuditSummaryQuery.hookName(e.getHook()), e.getVerdict(), e.getMode() == null ? null : e.getMode().name(),
                        e.getOrigin().name(), e.getTagSource().name(), e.getWarrantId(), e.getKernelSubjectId(), e.getPid(),
                        e.getUid(), e.getCgroupId(), e.getComm(), e.getDeviceId(), e.getInode(), e.getResolvedPath(),
                        e.getDestination()))
                .toList();
        return res.header(CURSOR, Long.toString(cursor)).body(body);
    }

    /**
     * 「구간 선택」 막대 집계. {@code [from, to)} 를 {@code bucketSeconds} 막대로 나눠 막대 · 훅 · 판정 · 영장 여부별 건수.
     * 막대 경계는 {@code origin} + k · bucket — 대시보드는 자기 지역 자정을 보내 하루 막대가 그 날짜에 맞는다.
     */
    @GetMapping("/summary")
    public List<AuditSummaryQuery.Row> summary(@RequestParam Instant from, @RequestParam Instant to,
                                               @RequestParam long bucketSeconds,
                                               @RequestParam(required = false) Instant origin,
                                               @RequestParam(required = false) String node) {
        if (!from.isBefore(to) || bucketSeconds < 1
                || Duration.between(from, to).toSeconds() / bucketSeconds > MAX_BUCKETS) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "need from < to and at most " + MAX_BUCKETS + " buckets");
        }
        return summaries.summary(from, to, bucketSeconds, origin != null ? origin : DEFAULT_ORIGIN, nodeIds(node));
    }

    // null = every node. A hostname is self-reported, so several nodes may share it.
    private List<UUID> nodeIds(String hostname) {
        return hostname == null ? null : nodes.findByHostname(hostname).stream().map(Node::getId).toList();
    }

    private static Specification<AuditEvent> matching(String kind, List<UUID> nodeIds) {
        Specification<AuditEvent> s = (e, q, cb) -> cb.conjunction();
        if ("verdict".equals(kind)) {
            s = s.and((e, q, cb) -> cb.and(cb.equal(e.get("origin"), AuditEvent.Origin.LSM),
                    e.get("type").in(AuditSummaryQuery.VERDICTS)));
        } else if (kind != null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "kind must be verdict");
        }
        if (nodeIds != null) {
            s = s.and((e, q, cb) -> nodeIds.isEmpty() ? cb.disjunction() : e.get("nodeId").in(nodeIds));
        }
        return s;
    }

    /**
     * 새 기록 알림(SSE). {@code event: audit} 의 data 는 새로 들어간 행 수뿐이다 — 기록은 위 조회로 가져온다.
     * 처음에 {@code event: ready} 가 한 번 온다.
     */
    @GetMapping(path = "/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter stream() {
        return stream.subscribe();
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
