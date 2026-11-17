package io.seswar.warrant.audit.store;

import io.seswar.warrant.audit.api.AuditQueryController;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

/**
 * 「조직 전체 SSH 접속 현황」— 영장 세션과 무영장 세션을 합친 뷰 {@code ssh_session}(V5)을 읽는다.
 *
 * <p>접속 한 번이 한 행이다. 그 안에서 무슨 일이 있었는지는 {@code audit_event} 가 cgroup 으로 들고 있다 —
 * 알갱이가 다른 질문이라 테이블을 따로 둔다. 천만 행짜리 감사 테이블을 접속 수를 세려고 훑지 않는다.
 */
@Repository
@RequiredArgsConstructor
public class SshSessionQuery {

    private final NamedParameterJdbcTemplate jdbc;

    /** 접속 한 번. 영장 세션이면 reason 이 null, 무영장이면 warrantId 가 0 이고 mode 가 null. */
    public record Row(Instant observedAt, UUID nodeId, boolean warranted, long warrantId, String mode, String reason,
                      String loginAccount, String sshKeyFingerprint, String sourceAddress, long cgroupId) {
    }

    // Called by AuditQueryController.sessions. `nodes` null means every node.
    public List<Row> sessions(Instant since, Instant until, Collection<UUID> nodes, int limit) {
        var p = new MapSqlParameterSource()
                .addValue("since", Timestamp.from(since))
                .addValue("until", Timestamp.from(until))
                .addValue("limit", limit);
        String nodeFilter = "";
        if (nodes != null) {
            if (nodes.isEmpty()) {
                return List.of();
            }
            nodeFilter = " and node_id in (:nodes)";
            p.addValue("nodes", nodes);
        }
        return jdbc.query("""
                select observed_at, node_id, warranted, warrant_id, mode, reason,
                       login_account, ssh_key_fingerprint, source_address, cgroup_id
                from ssh_session
                where observed_at >= :since and observed_at < :until""" + nodeFilter + """

                order by observed_at desc
                limit :limit
                """, p, (rs, i) -> new Row(
                rs.getTimestamp("observed_at").toInstant(),
                rs.getObject("node_id", UUID.class),
                rs.getBoolean("warranted"),
                rs.getLong("warrant_id"),
                rs.getString("mode"),
                rs.getString("reason"),
                rs.getString("login_account"),
                rs.getString("ssh_key_fingerprint"),
                rs.getString("source_address"),
                rs.getLong("cgroup_id")));
    }
}
