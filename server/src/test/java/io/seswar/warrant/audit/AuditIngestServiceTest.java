package io.seswar.warrant.audit;

import io.seswar.warrant.audit.store.AuditEvent;
import io.seswar.warrant.audit.store.AuditEventRepository;
import io.seswar.warrant.audit.store.AuditEventType;
import io.seswar.warrant.audit.store.EventGap;
import io.seswar.warrant.audit.store.UnwarrantedSession;
import io.seswar.warrant.audit.store.Verdict;
import io.seswar.warrant.audit.store.WarrantedSession;
import io.seswar.warrant.audit.store.WriteAggregate;
import io.seswar.warrant.audit.AuditIngestService.Batch;
import io.seswar.warrant.audit.AuditIngestService.Result;
import io.seswar.warrant.node.Node;
import io.seswar.warrant.node.NodeRepository;
import io.seswar.warrant.warrant.store.WarrantMode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.util.ReflectionTestUtils;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

// Real PostgreSQL 18 with Flyway V1 + V2. One batch = what one AuditBatch carries.
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Testcontainers
@Import(AuditIngestService.class)
class AuditIngestServiceTest {

    @Container
    @ServiceConnection
    static PostgreSQLContainer postgres = new PostgreSQLContainer("postgres:18");

    @Autowired AuditIngestService ingest;
    @Autowired AuditEventRepository events;
    @Autowired NodeRepository nodes;
    @Autowired JdbcTemplate jdbc;

    static final Instant T = Instant.parse("2026-10-20T00:00:00Z");
    UUID nodeId;

    @BeforeEach
    void node() {
        Node n = new Node();
        ReflectionTestUtils.setField(n, "clientCertFingerprint", "cert-" + UUID.randomUUID());
        ReflectionTestUtils.setField(n, "hostname", "node-a");
        ReflectionTestUtils.setField(n, "attachedHooks", Set.of());
        nodeId = (UUID) ReflectionTestUtils.getField(nodes.saveAndFlush(n), "id");
    }

    private AuditEvent unwarrantedEvent(long epoch, long seq) {
        return AuditEvent.builder()
                .occurredAt(T.plusSeconds(seq)).nodeId(nodeId).seqEpoch(epoch).nodeSeq(seq)
                .type(AuditEventType.UNWARRANTED_SESSION).verdict(Verdict.ALLOW)
                .tagSource(AuditEvent.TagSource.NONE).origin(AuditEvent.Origin.AGENT).cgroupId(7594L)
                .build();
    }

    private Batch batch(long epoch, long seq) {
        return new Batch(
                List.of(unwarrantedEvent(epoch, seq)),
                List.of(EventGap.of(nodeId, T, T.plusSeconds(5), null, "RINGBUF_OVERFLOW")),
                List.of(UnwarrantedSession.of(nodeId, epoch, seq, T.plusSeconds(seq),
                        "ec2-user", null, "10.0.0.5", 7594, "NO_KEY")));
    }

    private long count(String table) {
        return jdbc.queryForObject("select count(*) from " + table, Long.class);
    }

    @Test
    void 배치를_받으면_감사기록_유실구간_무영장세션이_모두_저장된다() {
        assertThat(ingest.ingest(nodeId, batch(1, 1))).isEqualTo(new Result(1, 1, 1));
        assertThat(count("audit_event")).isEqualTo(1);
        assertThat(count("audit_gap")).isEqualTo(1);
        assertThat(jdbc.queryForObject("select reason from unwarranted_session", String.class)).isEqualTo("NO_KEY");
        assertThat(jdbc.queryForObject("select dropped_count from audit_gap", Long.class)).isNull();  // 모름 ≠ 0
    }

    @Test
    void 같은_배치가_다시_와도_중복_저장되지_않는다() {
        ingest.ingest(nodeId, batch(1, 1));
        assertThat(ingest.ingest(nodeId, batch(1, 1))).isEqualTo(new Result(0, 0, 0));
        assertThat(count("audit_event")).isEqualTo(1);
        assertThat(count("audit_gap")).isEqualTo(1);
        assertThat(count("unwarranted_session")).isEqualTo(1);
    }

    @Test
    void 노드의_로컬저장소가_초기화돼_순번이_1로_돌아가도_새_기록으로_저장된다() {
        ingest.ingest(nodeId, batch(1, 1));
        // bbolt 초기화 뒤 node_seq 가 1 로 돌아왔다. 유실 구간은 같은 것이라 건너뛴다
        assertThat(ingest.ingest(nodeId, batch(2, 1))).isEqualTo(new Result(1, 0, 1));
        assertThat(count("unwarranted_session")).isEqualTo(2);
    }

    @Test
    void 한_배치_안에_같은_기록이_두_번_있으면_한_번만_저장된다() {
        EventGap gap = EventGap.of(nodeId, T, T.plusSeconds(5), 3L, "CPU_SEQ_SKIP");
        Batch twice = new Batch(
                List.of(unwarrantedEvent(1, 1), unwarrantedEvent(1, 1)),
                List.of(gap, EventGap.of(nodeId, T, T.plusSeconds(5), 3L, "CPU_SEQ_SKIP")),
                List.of());
        assertThat(ingest.ingest(nodeId, twice)).isEqualTo(new Result(1, 1, 0));
    }

    private Batch warrantedBatch(long epoch, long seq) {
        AuditEvent e = AuditEvent.builder()
                .occurredAt(T.plusSeconds(seq)).nodeId(nodeId).seqEpoch(epoch).nodeSeq(seq)
                .type(AuditEventType.WARRANTED_SESSION).verdict(Verdict.ALLOW).warrantId(9L)
                .tagSource(AuditEvent.TagSource.CGROUP).origin(AuditEvent.Origin.AGENT).cgroupId(7594L)
                .build();
        return new Batch(List.of(e), List.of(), List.of(), List.of(WarrantedSession.of(nodeId, epoch, seq,
                T.plusSeconds(seq), 9, 42, "DRYRUN", "ec2-user", "SHA256:abc", "10.0.0.5", 7594)));
    }

    @Test
    void 영장_세션도_다시_와도_한_번만_남는다() {
        assertThat(ingest.ingest(nodeId, warrantedBatch(1, 1))).isEqualTo(new Result(1, 0, 0, 1));
        assertThat(ingest.ingest(nodeId, warrantedBatch(1, 1))).isEqualTo(new Result(0, 0, 0, 0));
        assertThat(jdbc.queryForObject("select source_address from warranted_session", String.class)).isEqualTo("10.0.0.5");
        assertThat(count("warranted_session")).isEqualTo(1);
    }

    // 「조직 전체 SSH 접속 현황」은 영장 세션과 무영장 세션을 한 줄씩 나란히 본다.
    @Test
    void 접속_현황에는_영장_세션과_무영장_세션이_함께_보인다() {
        ingest.ingest(nodeId, batch(1, 1));
        ingest.ingest(nodeId, warrantedBatch(1, 2));
        assertThat(jdbc.queryForList("select warranted from ssh_session order by observed_at", Boolean.class))
                .containsExactly(false, true);
        assertThat(jdbc.queryForObject("select reason from ssh_session where warranted", String.class)).isNull();
        assertThat(jdbc.queryForObject("select warrant_id from ssh_session where not warranted", Long.class)).isZero();
    }

    private static final long MINUTE_NS = 60_000_000_000L;

    private Batch writes(WriteAggregate... rows) {
        return new Batch(List.of(), List.of(), List.of(), List.of(), List.of(rows));
    }

    private WriteAggregate write(long warrantId, long count) {
        return new WriteAggregate(nodeId, warrantId, T, MINUTE_NS, count);
    }

    private long allowed(long warrantId) {
        return jdbc.queryForObject("select allowed_count from write_aggregate where warrant_id = ?", Long.class, warrantId);
    }

    @Test
    void 쓰기_허용_집계가_영장_막대별로_저장된다() {
        ingest.ingest(nodeId, writes(write(9, 12), write(10, 3)));

        assertThat(count("write_aggregate")).isEqualTo(2);
        assertThat(allowed(9)).isEqualTo(12);
        assertThat(jdbc.queryForObject("select bucket_ns from write_aggregate where warrant_id = 9", Long.class))
                .isEqualTo(MINUTE_NS);
    }

    @Test
    void 같은_쓰기_집계가_다시_와도_건수가_부풀지_않는다() {
        ingest.ingest(nodeId, writes(write(9, 12)));
        ingest.ingest(nodeId, writes(write(9, 12)));  // 재전송

        assertThat(count("write_aggregate")).isEqualTo(1);
        assertThat(allowed(9)).isEqualTo(12);
    }

    @Test
    void 막대가_닫히기_전_중간값이_와도_큰_값이_남는다() {
        ingest.ingest(nodeId, writes(write(9, 5)));
        ingest.ingest(nodeId, writes(write(9, 12)));
        ingest.ingest(nodeId, writes(write(9, 5)));  // 옛 배치가 늦게 재전송됐다 — 줄어들면 안 된다

        assertThat(allowed(9)).isEqualTo(12);
    }

    @Test
    void 한_배치_안에_같은_칸이_두_번_있어도_큰_값_하나로_저장된다() {
        // pgjdbc 가 다중 행 INSERT 로 묶으면 같은 행을 두 번 고치는 ON CONFLICT 는 PostgreSQL 이 거부한다
        ingest.ingest(nodeId, writes(write(9, 5), write(9, 12), write(9, 7)));

        assertThat(count("write_aggregate")).isEqualTo(1);
        assertThat(allowed(9)).isEqualTo(12);
    }

    @Test
    void 다른_막대나_다른_노드면_다른_칸이다() {
        ingest.ingest(nodeId, writes(write(9, 5),
                new WriteAggregate(nodeId, 9, T.plusSeconds(60), MINUTE_NS, 4)));

        assertThat(count("write_aggregate")).isEqualTo(2);
    }

    @Test
    void 남의_노드_쓰기_집계가_섞인_배치는_거부된다() {
        Batch mixed = writes(new WriteAggregate(UUID.randomUUID(), 9, T, MINUTE_NS, 1));
        assertThatThrownBy(() -> ingest.ingest(nodeId, mixed)).isInstanceOf(IllegalArgumentException.class);
        assertThat(count("write_aggregate")).isZero();
    }

    // 감사 기록은 엔티티가 아니라 JDBC 로 넣는다(AuditIngestService.INSERT_EVENT). 칸을 하나 빠뜨리면 조용히 비어 들어간다.
    private AuditEvent everyColumnFilled() {
        return AuditEvent.builder()
                .occurredAt(T.plusMillis(1234)).nodeId(nodeId).seqEpoch(11).nodeSeq(22).warrantId(33)
                .kernelSubjectId(44).type(AuditEventType.FILE_WRITE).verdict(Verdict.WOULD_DENY)
                .mode(WarrantMode.DRYRUN).tagSource(AuditEvent.TagSource.TASK).origin(AuditEvent.Origin.KPROBE)
                .pid(55L).cgroupId(66L).uid(77).deviceId(88L).inode(99L).resolvedPath("/etc/app/conf")
                .argvTruncated("cp a b").destination("10.0.0.9:443").hook((short) 5).comm("cp")
                .build();
    }

    @Test
    void 감사_기록의_모든_칸이_넣은_값_그대로_다시_읽힌다() throws IllegalAccessException {
        AuditEvent sent = everyColumnFilled();
        for (Field f : AuditEvent.class.getDeclaredFields()) {
            if (Modifier.isStatic(f.getModifiers()) || Set.of("id", "receivedSeq").contains(f.getName())) {
                continue;
            }
            f.setAccessible(true);
            assertThat(f.get(sent)).as("AuditEvent.%s 가 비어 있다 — 새 칸이면 위 예시에도 값을 채운다", f.getName()).isNotNull();
        }

        ingest.ingest(nodeId, new Batch(List.of(sent), List.of(), List.of()));

        assertThat(events.findAll()).singleElement()
                .usingRecursiveComparison().ignoringFields("id", "receivedSeq").isEqualTo(sent);
    }

    @Test
    void 감사_표의_칸이_빠짐없이_저장_문에_들어_있다() {
        List<String> table = jdbc.queryForList("""
                select column_name from information_schema.columns
                where table_schema = current_schema() and table_name = 'audit_event'""", String.class);
        String sql = AuditIngestService.INSERT_EVENT;
        List<String> inserted = Arrays.stream(sql.substring(sql.indexOf('(') + 1, sql.indexOf(')')).split(","))
                .map(String::strip).toList();

        // id 와 received_seq 는 DB 기본값(gen_random_uuid · nextval)이 채운다
        assertThat(inserted).containsExactlyInAnyOrderElementsOf(
                table.stream().filter(c -> !Set.of("id", "received_seq").contains(c)).toList());
    }

    @Test
    void 다른_노드의_기록이_섞인_배치는_통째로_거부된다() {
        Batch foreign = new Batch(List.of(), List.of(EventGap.of(UUID.randomUUID(), T, T, 0L, "AGENT_DOWN")), List.of());
        assertThatThrownBy(() -> ingest.ingest(nodeId, foreign)).isInstanceOf(IllegalArgumentException.class);
        assertThat(count("audit_gap")).isZero();
    }
}
