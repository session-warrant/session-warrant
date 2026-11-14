package io.seswar.warrant.audit;

import io.seswar.warrant.proto.AuditProtos.Hook;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * 대시보드 「구간 선택」의 막대 집계. 원본을 다 내려보내지 않고 막대 · 훅 · 판정별 건수만 준다 — 일주일이면 원본이 수십만 건이다.
 * 센 것은 LSM 판정뿐이다(kprobe 미러는 같은 판정을 한 번 더 세고, fork 는 판정이 아니다).
 */
@Repository
@RequiredArgsConstructor
public class AuditSummaryQuery {

    /** 판정 기록의 종류. 원본 조회의 {@code kind=verdict} 도 같은 목록을 쓴다. */
    static final Set<AuditEventType> VERDICTS = Set.of(AuditEventType.EXEC, AuditEventType.FILE_WRITE,
            AuditEventType.INODE_MUTATE, AuditEventType.CONNECT, AuditEventType.UDP_SEND, AuditEventType.SELF_PROTECTION_HIT);

    private final NamedParameterJdbcTemplate jdbc;

    public record Row(Instant t, String hook, Verdict verdict, boolean warranted, long n) {
    }

    // Called by AuditQueryController.summary. `nodes` null means every node. Bucket edges are origin + k * bucket.
    List<Row> summary(Instant from, Instant to, long bucketSeconds, Instant origin, Collection<UUID> nodes) {
        var p = new MapSqlParameterSource()
                .addValue("bucket", bucketSeconds)
                .addValue("origin", Timestamp.from(origin))
                .addValue("from", Timestamp.from(from))
                .addValue("to", Timestamp.from(to))
                .addValue("lsm", AuditEvent.Origin.LSM.wireValue())
                .addValue("types", VERDICTS.stream().map(Enum::name).collect(Collectors.toList()));
        String nodeFilter = "";
        if (nodes != null) {
            if (nodes.isEmpty()) {
                return List.of();
            }
            nodeFilter = " and node_id in (:nodes)";
            p.addValue("nodes", nodes);
        }
        return jdbc.query("""
                select date_bin(make_interval(secs => :bucket), occurred_at, :origin) as t,
                       hook, verdict, warrant_id <> 0 as warranted, count(*) as n
                from audit_event
                where occurred_at >= :from and occurred_at < :to and origin = :lsm and type in (:types)""" + nodeFilter + """

                group by 1, 2, 3, 4
                order by 1
                """, p, (rs, i) -> new Row(rs.getTimestamp("t").toInstant(), hookName(rs.getObject("hook", Short.class)),
                Verdict.fromWire(rs.getInt("verdict")), rs.getBoolean("warranted"), rs.getLong("n")));
    }

    // Rows stored before V3 have no hook.
    static String hookName(Short hook) {
        if (hook == null) {
            return null;
        }
        Hook h = Hook.forNumber(hook);
        return h == null ? String.valueOf(hook) : h.name();
    }
}
