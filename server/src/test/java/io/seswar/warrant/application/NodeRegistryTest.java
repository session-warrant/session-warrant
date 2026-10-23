package io.seswar.warrant.application;

import io.seswar.warrant.application.NodeRegistry.Registration;
import io.seswar.warrant.application.NodeRegistry.Report;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

// Real PostgreSQL 18. The clock is a test clock so lastSeenAt and staleness are deterministic.
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Testcontainers
@Import({NodeRegistry.class, NodeRegistryTest.Clocks.class})
class NodeRegistryTest {

    @Container
    @ServiceConnection
    static PostgreSQLContainer postgres = new PostgreSQLContainer("postgres:18");

    static final Instant T0 = Instant.parse("2026-10-20T00:00:00Z");

    /** 테스트가 앞으로 돌릴 수 있는 시계. */
    static final class TestClock extends Clock {
        Instant now = T0;

        void advance(Duration d) { now = now.plus(d); }

        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
    }

    @TestConfiguration
    static class Clocks {
        @Bean
        TestClock clock() {
            return new TestClock();
        }
    }

    @Autowired NodeRegistry registry;
    @Autowired TestClock clock;
    @Autowired JdbcTemplate jdbc;

    // The clock bean is shared by every test in this class; start each one at T0.
    @BeforeEach
    void resetClock() {
        clock.now = T0;
    }

    private static Report report(String hostname, Set<String> hooks, long epoch) {
        return new Report(hostname, "7.0.0-15-generic", true, "warrantd 0.1.0", hooks,
                Instant.parse("2026-10-19T23:00:00Z"), epoch);
    }

    private Map<String, Object> row(UUID nodeId) {
        return jdbc.queryForMap("select * from node where id = ?", nodeId);
    }

    @Test
    void 처음_접속한_노드는_새로_등록된다() {
        Registration r = registry.register("dev:node-a", report("node-a", Set.of("HOOK_BPRM_CHECK_SECURITY"), 7));

        assertThat(r.created()).isTrue();
        assertThat(r.epochChanged()).isFalse();  // 처음 보는 노드는 바뀐 게 아니다
        Map<String, Object> row = row(r.nodeId());
        assertThat(row.get("client_cert_fingerprint")).isEqualTo("dev:node-a");
        assertThat(row.get("hostname")).isEqualTo("node-a");
        assertThat(row.get("bpf_lsm_enabled")).isEqualTo(true);
        assertThat(row.get("current_seq_epoch")).isEqualTo(7L);
        assertThat(row.get("last_seen_at")).isNotNull();
    }

    @Test
    void 같은_노드가_다시_접속하면_새로_만들지_않는다() {
        UUID first = registry.register("dev:node-a", report("node-a", Set.of(), 7)).nodeId();
        Registration again = registry.register("dev:node-a", report("node-a", Set.of(), 7));

        assertThat(again.nodeId()).isEqualTo(first);
        assertThat(again.created()).isFalse();
        assertThat(jdbc.queryForObject("select count(*) from node", Long.class)).isEqualTo(1);
    }

    @Test
    void 다시_접속하면_노드가_알려준_정보로_갱신된다() {
        UUID id = registry.register("dev:node-a", report("node-a", Set.of("HOOK_SCHED_PROCESS_FORK"), 7)).nodeId();
        clock.advance(Duration.ofMinutes(5));
        registry.register("dev:node-a", new Report("node-a-renamed", "7.0.1", false, "warrantd 0.2.0",
                Set.of("HOOK_SCHED_PROCESS_FORK", "HOOK_BPRM_CHECK_SECURITY"), T0, 7));

        Map<String, Object> row = row(id);
        assertThat(row.get("hostname")).isEqualTo("node-a-renamed");  // 신원은 identity, hostname 은 신고값일 뿐
        assertThat(row.get("kernel_version")).isEqualTo("7.0.1");
        assertThat(row.get("bpf_lsm_enabled")).isEqualTo(false);
        assertThat(row.get("agent_version")).isEqualTo("warrantd 0.2.0");
        assertThat(jdbc.queryForList("select unnest(attached_hooks) from node where id = ?", String.class, id))
                .containsExactlyInAnyOrder("HOOK_SCHED_PROCESS_FORK", "HOOK_BPRM_CHECK_SECURITY");
        assertThat(jdbc.queryForObject("select last_seen_at from node where id = ?", java.sql.Timestamp.class, id)
                .toInstant()).isEqualTo(T0.plus(Duration.ofMinutes(5)));
    }

    @Test
    void 노드의_로컬저장소가_초기화되면_알아챈다() {
        UUID id = registry.register("dev:node-a", report("node-a", Set.of(), 7)).nodeId();

        assertThat(registry.register("dev:node-a", report("node-a", Set.of(), 7)).epochChanged()).isFalse();
        assertThat(registry.register("dev:node-a", report("node-a", Set.of(), 8)).epochChanged()).isTrue();
        assertThat(row(id).get("current_seq_epoch")).isEqualTo(8L);
    }

    @Test
    void 이름이_같아도_인증서가_다르면_다른_노드다() {
        UUID a = registry.register("dev:node-a", report("same-host", Set.of(), 1)).nodeId();
        UUID b = registry.register("dev:node-b", report("same-host", Set.of(), 1)).nodeId();
        assertThat(a).isNotEqualTo(b);  // hostname 이 같아도 신원이 다르면 다른 노드
    }

    @Test
    void 오래_소식이_없는_노드만_끊긴_노드로_나온다() {
        UUID quiet = registry.register("dev:quiet", report("quiet", Set.of(), 1)).nodeId();
        UUID alive = registry.register("dev:alive", report("alive", Set.of(), 1)).nodeId();

        clock.advance(Duration.ofMinutes(10));
        registry.heartbeat(alive);
        clock.advance(Duration.ofMinutes(1));

        List<UUID> stale = registry.staleNodes(Duration.ofMinutes(5));
        assertThat(stale).containsExactly(quiet);
        assertThat(stale).doesNotContain(alive);
    }
}
