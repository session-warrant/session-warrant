package io.seswar.warrant.grpc;

import io.seswar.warrant.application.AuditIngestService;
import io.seswar.warrant.application.NodeRegistry;
import io.seswar.warrant.domain.audit.AuditEvent;
import io.seswar.warrant.domain.audit.AuditEventType;
import io.seswar.warrant.domain.audit.EventGap;
import io.seswar.warrant.domain.audit.UnwarrantedSession;
import io.seswar.warrant.domain.audit.Verdict;
import io.seswar.warrant.domain.warrant.WarrantMode;
import io.seswar.warrant.proto.AgentProtos.AuditBatch;
import io.seswar.warrant.proto.AgentProtos.NodeHello;
import io.seswar.warrant.proto.AuditProtos;
import io.seswar.warrant.proto.AuditProtos.ConnectEvent;
import io.seswar.warrant.proto.AuditProtos.FileRef;
import io.seswar.warrant.proto.AuditProtos.GapReport;
import io.seswar.warrant.proto.AuditProtos.UnwarrantedSessionEvent;
import lombok.NoArgsConstructor;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/** proto ↔ 서버 엔티티. 변환 규칙은 AuditProtoMapperTest 가 정한다. */
@NoArgsConstructor
public final class AuditProtoMapper {

    private static final long NANOS_PER_SECOND = 1_000_000_000L;


    /** AuditBatch를 서버에서 사용할 batch로 전환 */
    public static AuditIngestService.Batch toBatch(UUID nodeId, AuditBatch batch) {
        // No table yet. Ignoring them would ack them and warrantd would delete them.
        if (batch.getWriteAggregatesCount() > 0) {
            throw new IllegalArgumentException("write_aggregates are not stored yet ("
                    + batch.getWriteAggregatesCount() + " in batch)");
        }
        long epoch = batch.getSeqEpoch();
        List<AuditEvent> events = new ArrayList<>();
        List<UnwarrantedSession> sessions = new ArrayList<>();
        for (AuditProtos.AuditEvent p : batch.getEventsList()) {
            AuditEvent e = toEvent(nodeId, epoch, p);
            events.add(e);
            if (p.hasUnwarrantedSession()) {
                sessions.add(toSession(e, p.getUnwarrantedSession()));
            }
        }
        List<EventGap> gaps = batch.getGapsList().stream().map(g -> toGap(nodeId, g)).toList();
        return new AuditIngestService.Batch(events, gaps, sessions);
    }

    /** 첫 배치에 실려온 NodeHello를 노드 등록에 쓸 NodeRegistry.Report로 전환*/
    public static NodeRegistry.Report toReport(NodeHello hello, long seqEpoch) {
        if (hello.getHostname().isEmpty()) {
            throw new IllegalArgumentException("NodeHello without hostname");
        }
        Set<String> hooks = hello.getAttachedHooksList().stream().map(Enum::name).collect(Collectors.toSet());
        Instant bootedAt = hello.getBootedAtUnixNs() == 0 ? null : instant(hello.getBootedAtUnixNs());
        return new NodeRegistry.Report(hello.getHostname(), emptyToNull(hello.getKernelVersion()),
                hello.getBpfLsmEnabled(), emptyToNull(hello.getAgentVersion()), hooks, bootedAt, seqEpoch);
    }

    private static AuditEvent toEvent(UUID nodeId, long epoch, AuditProtos.AuditEvent p) {
        AuditEvent.AuditEventBuilder b = AuditEvent.builder()
                .nodeId(nodeId)
                .seqEpoch(epoch)
                .nodeSeq(p.getNodeSeq())
                .occurredAt(requiredInstant(p.getWallTsUnixNs(), "wall_ts_unix_ns"))
                .type(typeOf(p.getPayloadCase()))
                .verdict(Verdict.fromWire(p.getVerdictValue()))
                .mode(WarrantMode.fromWire(p.getModeValue()))
                .origin(AuditEvent.Origin.fromWire(p.getOriginValue()))
                .tagSource(AuditEvent.TagSource.fromWire(p.getTagSourceValue()))
                .warrantId(p.getWarrantId())
                .kernelSubjectId(p.getSubjectId() == 0 ? null : p.getSubjectId());

        if (p.hasProcess()) {
            AuditProtos.ProcessIdentity proc = p.getProcess();
            b.pid(Integer.toUnsignedLong(proc.getTgid()))
                    .uid(proc.getUid())
                    .cgroupId(proc.getCgroupId());
        }

        switch (p.getPayloadCase()) {
            case EXEC -> {
                if (p.getExec().hasFile()) {
                    file(b, p.getExec().getFile());
                }
                b.argvTruncated(emptyToNull(p.getExec().getArgv()));
            }
            case FILE_WRITE -> {
                if (p.getFileWrite().hasFile()) {
                    file(b, p.getFileWrite().getFile());
                }
            }
            case INODE_MUTATE -> {
                if (p.getInodeMutate().hasDir()) {
                    file(b, p.getInodeMutate().getDir());
                }
            }
            case SELF_PROTECTION -> {
                if (p.getSelfProtection().hasFile()) {
                    file(b, p.getSelfProtection().getFile());
                }
            }
            case CONNECT -> b.destination(destination(p.getConnect()));
            case UDP_SEND -> b.destination(destination(p.getUdpSend().getDestination()));
            case UNWARRANTED_SESSION -> {
                if (!p.hasProcess()) {
                    b.cgroupId(p.getUnwarrantedSession().getCgroupId());
                }
            }
            default -> {
                // FORK · DELEGATION_ATTEMPT · GRACE · SHELL_COMMAND_LINE: 공통 칸만. 칸별 변환은 필요할 때 늘린다
            }
        }
        return b.build();
    }

    private static AuditEventType typeOf(AuditProtos.AuditEvent.PayloadCase c) {
        return switch (c) {
            case EXEC -> AuditEventType.EXEC;
            case FILE_WRITE -> AuditEventType.FILE_WRITE;
            case INODE_MUTATE -> AuditEventType.INODE_MUTATE;
            case CONNECT -> AuditEventType.CONNECT;
            case UDP_SEND -> AuditEventType.UDP_SEND;
            case SELF_PROTECTION -> AuditEventType.SELF_PROTECTION_HIT;
            case FORK -> AuditEventType.FORK;
            case UNWARRANTED_SESSION -> AuditEventType.UNWARRANTED_SESSION;
            case DELEGATION_ATTEMPT -> AuditEventType.DELEGATION_ATTEMPT;
            case GRACE -> AuditEventType.GRACE;
            case SHELL_COMMAND_LINE -> AuditEventType.SHELL_COMMAND_LINE;
            case PAYLOAD_NOT_SET -> throw new IllegalArgumentException("audit event without payload");
        };
    }

    private static UnwarrantedSession toSession(AuditEvent e, UnwarrantedSessionEvent u) {
        if (u.getReason() == UnwarrantedSessionEvent.Reason.REASON_UNSPECIFIED
                || u.getReason() == UnwarrantedSessionEvent.Reason.UNRECOGNIZED) {
            throw new IllegalArgumentException("unwarranted session without a known reason: " + u.getReasonValue());
        }
        return UnwarrantedSession.of(e.getNodeId(), e.getSeqEpoch(), e.getNodeSeq(), e.getOccurredAt(),
                emptyToNull(u.getLoginAccount()), emptyToNull(u.getSshKeyFingerprint()),
                emptyToNull(u.getSourceAddress()), u.getCgroupId(), stripPrefix(u.getReason().name(), "REASON_"));
    }

    private static EventGap toGap(UUID nodeId, GapReport g) {
        if (g.getCause() == GapReport.Cause.CAUSE_UNSPECIFIED || g.getCause() == GapReport.Cause.UNRECOGNIZED) {
            throw new IllegalArgumentException("gap without a known cause: " + g.getCauseValue());
        }
        return EventGap.of(nodeId,
                requiredInstant(g.getFromUnixNs(), "gap from_unix_ns"),
                requiredInstant(g.getToUnixNs(), "gap to_unix_ns"),
                g.getDroppedCountKnown() ? g.getDroppedCount() : null,
                stripPrefix(g.getCause().name(), "CAUSE_"));
    }

    // dev is the kernel's u32 s_dev; Java reads fixed32 as signed int.
    private static void file(AuditEvent.AuditEventBuilder b, FileRef f) {
        b.deviceId(Integer.toUnsignedLong(f.getDev()))
                .inode(f.getIno())
                .resolvedPath(emptyToNull(f.getPath()));
    }

    private static String destination(ConnectEvent c) {
        return switch (c.getFamily()) {
            case FAMILY_INET -> address(c) + ":" + c.getPort();
            case FAMILY_INET6 -> "[" + address(c) + "]:" + c.getPort();
            case FAMILY_UNIX -> c.getAbstract() ? "@" + c.getSunPath() : c.getSunPath();
            default -> null;
        };
    }

    private static String address(ConnectEvent c) {
        try {
            return InetAddress.getByAddress(c.getAddr().toByteArray()).getHostAddress();
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("bad connect address of " + c.getAddr().size() + " bytes", e);
        }
    }

    // 0 means "not filled in". Accepting it would put the row in 1970 silently.
    private static Instant requiredInstant(long unixNs, String field) {
        if (unixNs == 0) {
            throw new IllegalArgumentException(field + " is 0");
        }
        return instant(unixNs);
    }

    private static Instant instant(long unixNs) {
        return Instant.ofEpochSecond(Math.floorDiv(unixNs, NANOS_PER_SECOND), Math.floorMod(unixNs, NANOS_PER_SECOND));
    }

    private static String emptyToNull(String s) {
        return s.isEmpty() ? null : s;
    }

    private static String stripPrefix(String s, String prefix) {
        return s.startsWith(prefix) ? s.substring(prefix.length()) : s;
    }
}
