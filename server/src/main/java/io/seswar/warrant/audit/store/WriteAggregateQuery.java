package io.seswar.warrant.audit.store;

import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

/** 허용된 쓰기 집계({@code write_aggregate}, V6) 읽기. 막대 시작 최신 순. */
@Repository
@RequiredArgsConstructor
public class WriteAggregateQuery {

    private final NamedParameterJdbcTemplate jdbc;

    // Called by AuditQueryController.writes. `nodes` null means every node, `warrantId` null every warrant.
    public List<WriteAggregate> rows(Instant since, Instant until, Collection<UUID> nodes, Long warrantId, int limit) {
        var p = new MapSqlParameterSource()
                .addValue("since", Timestamp.from(since))
                .addValue("until", Timestamp.from(until))
                .addValue("limit", limit);
        StringBuilder where = new StringBuilder("bucket_start >= :since and bucket_start < :until");
        if (nodes != null) {
            if (nodes.isEmpty()) {
                return List.of();
            }
            where.append(" and node_id in (:nodes)");
            p.addValue("nodes", nodes);
        }
        if (warrantId != null) {
            where.append(" and warrant_id = :warrant");
            p.addValue("warrant", warrantId);
        }
        return jdbc.query("select node_id, warrant_id, bucket_start, bucket_ns, allowed_count from write_aggregate where "
                        + where + " order by bucket_start desc, warrant_id limit :limit",
                p, (rs, i) -> new WriteAggregate(
                        rs.getObject("node_id", UUID.class),
                        rs.getLong("warrant_id"),
                        rs.getTimestamp("bucket_start").toInstant(),
                        rs.getLong("bucket_ns"),
                        rs.getLong("allowed_count")));
    }
}
