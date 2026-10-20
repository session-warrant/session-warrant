package io.seswar.warrant.repository;

import io.seswar.warrant.domain.audit.AuditEvent;
import io.seswar.warrant.domain.audit.AuditEventType;
import io.seswar.warrant.domain.audit.UnwarrantedSession;
import io.seswar.warrant.domain.audit.Verdict;
import io.seswar.warrant.domain.node.Node;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.util.ReflectionTestUtils;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

// Real PostgreSQL 18 with Flyway V1 applied. Entities have no setters yet, so fields are set by reflection.
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Testcontainers
class AuditRepositoriesTest {

    @Container
    @ServiceConnection
    static PostgreSQLContainer postgres = new PostgreSQLContainer("postgres:18");

    @Autowired NodeRepository nodes;
    @Autowired AuditEventRepository events;
    @Autowired UnwarrantedSessionRepository sessions;
    @Autowired JdbcTemplate jdbc;

    private static <T> T with(T entity, Map<String, Object> fields) {
        fields.forEach((k, v) -> ReflectionTestUtils.setField(entity, k, v));
        return entity;
    }

    private Node node(String fingerprint) {
        return nodes.saveAndFlush(with(new Node(), Map.of(
                "clientCertFingerprint", fingerprint,
                "hostname", "node-a",
                "attachedHooks", Set.of("HOOK_BPRM_CHECK_SECURITY", "HOOK_SCHED_PROCESS_FORK"))));
    }

    static AuditEvent event(UUID nodeId, long epoch, long seq, Instant at) {
        return AuditEvent.builder()
                .occurredAt(at).nodeId(nodeId).seqEpoch(epoch).nodeSeq(seq)
                .type(AuditEventType.EXEC).verdict(Verdict.ALLOW)
                .tagSource(AuditEvent.TagSource.CGROUP).origin(AuditEvent.Origin.LSM)
                .build();
    }

    @Test
    void nodeRoundTripsTextArrayAndIsFoundByFingerprint() {
        node("cert-a");
        Node found = nodes.findByClientCertFingerprint("cert-a").orElseThrow();
        assertThat(ReflectionTestUtils.getField(found, "attachedHooks"))
                .isEqualTo(Set.of("HOOK_BPRM_CHECK_SECURITY", "HOOK_SCHED_PROCESS_FORK"));
    }

    @Test
    void findExistingKeysSeesOnlyThisNodeAndEpoch() {
        UUID nodeId = (UUID) ReflectionTestUtils.getField(node("cert-b"), "id");
        UUID other = (UUID) ReflectionTestUtils.getField(node("cert-b2"), "id");
        Instant t = Instant.parse("2026-10-20T00:00:00Z");
        events.saveAllAndFlush(List.of(event(nodeId, 7, 1, t), event(nodeId, 7, 2, t), event(nodeId, 8, 1, t),
                event(other, 7, 3, t)));

        assertThat(events.findExistingKeys(nodeId, Set.of(7L), 1, 3))
                .containsExactlyInAnyOrder(new SeqKey(7, 1), new SeqKey(7, 2));
        assertThat(jdbc.queryForObject("select origin from audit_event where node_seq = 2", Short.class))
                .isEqualTo((short) 1);  // proto ORIGIN_LSM, not the Java ordinal
        assertThat(events.findAll()).extracting(AuditEvent::getOrigin).containsOnly(AuditEvent.Origin.LSM);
    }

    @Test
    void summarizesUnwarrantedSessionsInHalfOpenRange() {
        UUID nodeId = (UUID) ReflectionTestUtils.getField(node("cert-c"), "id");
        Instant t = Instant.parse("2026-10-20T00:00:00Z");
        long seq = 0;
        for (Instant at : List.of(t, t.plusSeconds(60), t.plusSeconds(3600))) {
            UnwarrantedSession u = UnwarrantedSession.of(nodeId, 1, ++seq, at, "ec2-user", null, "10.0.0.5", 7594, "NO_KEY");
            sessions.save(with(u, Map.of("observedEventCount", 5L)));
        }
        sessions.flush();

        var byNode = sessions.summarizeByNode(t, t.plusSeconds(3600));  // 끝 시각은 제외
        assertThat(byNode).singleElement().satisfies(s -> {
            assertThat(s.getNodeId()).isEqualTo(nodeId);
            assertThat(s.getSessions()).isEqualTo(2);
            assertThat(s.getEvents()).isEqualTo(10);
        });
        assertThat(sessions.summarizeByAccount(t, t.plusSeconds(7200)))
                .singleElement().satisfies(s -> assertThat(s.getSessions()).isEqualTo(3));
    }
}
