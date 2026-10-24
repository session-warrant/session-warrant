package io.seswar.warrant.application;

import io.seswar.warrant.application.AuditIngestService.Batch;
import io.seswar.warrant.application.AuditIngestService.Result;
import io.seswar.warrant.domain.audit.AuditEvent;
import io.seswar.warrant.domain.audit.AuditEventType;
import io.seswar.warrant.domain.audit.EventGap;
import io.seswar.warrant.domain.audit.UnwarrantedSession;
import io.seswar.warrant.domain.audit.Verdict;
import io.seswar.warrant.domain.node.Node;
import io.seswar.warrant.repository.NodeRepository;
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

import java.time.Instant;
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

    @Test
    void 다른_노드의_기록이_섞인_배치는_통째로_거부된다() {
        Batch foreign = new Batch(List.of(), List.of(EventGap.of(UUID.randomUUID(), T, T, 0L, "AGENT_DOWN")), List.of());
        assertThatThrownBy(() -> ingest.ingest(nodeId, foreign)).isInstanceOf(IllegalArgumentException.class);
        assertThat(count("audit_gap")).isZero();
    }
}
