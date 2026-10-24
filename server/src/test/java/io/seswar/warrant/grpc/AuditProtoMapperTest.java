package io.seswar.warrant.grpc;

import com.google.protobuf.ByteString;
import io.seswar.warrant.application.AuditIngestService.Batch;
import io.seswar.warrant.application.NodeRegistry.Report;
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
import io.seswar.warrant.proto.AuditProtos.ExecEvent;
import io.seswar.warrant.proto.AuditProtos.FileRef;
import io.seswar.warrant.proto.AuditProtos.ForkEvent;
import io.seswar.warrant.proto.AuditProtos.GapReport;
import io.seswar.warrant.proto.AuditProtos.Hook;
import io.seswar.warrant.proto.AuditProtos.Origin;
import io.seswar.warrant.proto.AuditProtos.ProcessIdentity;
import io.seswar.warrant.proto.AuditProtos.TagSource;
import io.seswar.warrant.proto.AuditProtos.UnwarrantedSessionEvent;
import io.seswar.warrant.proto.AuditProtos.WriteAggregate;
import io.seswar.warrant.proto.WarrantProtos.Mode;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

// Pure conversion, no Spring or DB. Each test pins one rule of proto → entity.
class AuditProtoMapperTest {

    static final UUID NODE = UUID.fromString("00000000-0000-0000-0000-00000000000a");
    static final long EPOCH = 42;
    static final Instant T = Instant.parse("2026-10-20T00:00:00.123456789Z");
    static final long T_NS = T.getEpochSecond() * 1_000_000_000L + T.getNano();

    private static AuditProtos.AuditEvent.Builder base(long seq) {
        return AuditProtos.AuditEvent.newBuilder()
                .setNodeSeq(seq).setWallTsUnixNs(T_NS)
                .setHook(Hook.HOOK_BPRM_CHECK_SECURITY).setVerdict(AuditProtos.Verdict.VERDICT_ALLOW)
                .setMode(Mode.MODE_OBSERVE).setOrigin(Origin.ORIGIN_LSM).setTagSource(TagSource.TAG_CGROUP)
                .setWarrantId(7).setSubjectId(3)
                .setProcess(ProcessIdentity.newBuilder().setPid(101).setTgid(100).setUid(1000).setCgroupId(7594));
    }

    private static AuditProtos.AuditEvent unwarranted(long seq) {
        return AuditProtos.AuditEvent.newBuilder()
                .setNodeSeq(seq).setWallTsUnixNs(T_NS)
                .setHook(Hook.HOOK_AGENT).setVerdict(AuditProtos.Verdict.VERDICT_ALLOW)
                .setOrigin(Origin.ORIGIN_AGENT).setTagSource(TagSource.TAG_NONE)
                .setUnwarrantedSession(UnwarrantedSessionEvent.newBuilder()
                        .setLoginAccount("ec2-user").setSourceAddress("10.0.0.5").setCgroupId(7594)
                        .setSessionId("c1").setReason(UnwarrantedSessionEvent.Reason.REASON_NO_KEY))
                .build();
    }

    private static Batch map(AuditProtos.AuditEvent... events) {
        AuditBatch.Builder b = AuditBatch.newBuilder().setSeqEpoch(EPOCH);
        for (AuditProtos.AuditEvent e : events) {
            b.addEvents(e);
        }
        return AuditProtoMapper.toBatch(NODE, b.build());
    }

    private static AuditEvent only(AuditProtos.AuditEvent e) {
        return map(e).events().getFirst();
    }

    @Test
    void 감사기록의_공통_정보가_그대로_옮겨진다() {
        AuditEvent e = only(base(5).setExec(ExecEvent.getDefaultInstance()).build());

        assertThat(e.getNodeId()).isEqualTo(NODE);
        assertThat(e.getSeqEpoch()).isEqualTo(EPOCH);
        assertThat(e.getNodeSeq()).isEqualTo(5);
        assertThat(e.getOccurredAt()).isEqualTo(T);  // 나노초까지
        assertThat(e.getWarrantId()).isEqualTo(7);
        assertThat(e.getKernelSubjectId()).isEqualTo(3);
        assertThat(e.getVerdict()).isEqualTo(Verdict.ALLOW);
        assertThat(e.getMode()).isEqualTo(WarrantMode.OBSERVE);
        assertThat(e.getOrigin()).isEqualTo(AuditEvent.Origin.LSM);
        assertThat(e.getTagSource()).isEqualTo(AuditEvent.TagSource.CGROUP);
        assertThat(e.getPid()).isEqualTo(100L);  // 유저 공간의 PID 는 tgid
        assertThat(e.getUid()).isEqualTo(1000);
        assertThat(e.getCgroupId()).isEqualTo(7594L);
    }

    @Test
    void 기록_종류는_담긴_내용으로_정해진다() {
        assertThat(only(base(1).setExec(ExecEvent.getDefaultInstance()).build()).getType())
                .isEqualTo(AuditEventType.EXEC);
        assertThat(only(base(1).setConnect(ConnectEvent.getDefaultInstance()).build()).getType())
                .isEqualTo(AuditEventType.CONNECT);
        assertThat(only(base(1).setFork(ForkEvent.getDefaultInstance()).build()).getType())
                .isEqualTo(AuditEventType.FORK);
        assertThat(only(unwarranted(1)).getType()).isEqualTo(AuditEventType.UNWARRANTED_SESSION);
    }

    @Test
    void 실행_기록에는_실제로_실행된_파일과_명령줄이_남는다() {
        AuditEvent e = only(base(1).setExec(ExecEvent.newBuilder()
                .setFile(FileRef.newBuilder().setDev(0xF000_0001).setIno(1_234_567).setPath("/usr/bin/true"))
                .setArgv("true --flag")).build());

        assertThat(e.getDeviceId()).isEqualTo(0xF000_0001L);  // fixed32 는 부호 없는 u32
        assertThat(e.getInode()).isEqualTo(1_234_567L);
        assertThat(e.getResolvedPath()).isEqualTo("/usr/bin/true");
        assertThat(e.getArgvTruncated()).isEqualTo("true --flag");
    }

    @Test
    void 접속_기록에는_사람이_읽을_수_있는_목적지_주소가_남는다() {
        AuditEvent inet = only(base(1).setConnect(ConnectEvent.newBuilder()
                .setFamily(ConnectEvent.Family.FAMILY_INET)
                .setAddr(ByteString.copyFrom(new byte[]{10, 0, 0, 5})).setPort(443)).build());
        AuditEvent unix = only(base(2).setConnect(ConnectEvent.newBuilder()
                .setFamily(ConnectEvent.Family.FAMILY_UNIX).setSunPath("/run/systemd/private")).build());

        assertThat(inet.getDestination()).isEqualTo("10.0.0.5:443");
        assertThat(unix.getDestination()).isEqualTo("/run/systemd/private");
    }

    @Test
    void 무영장_접속은_감사기록과_무영장세션_두_곳에_함께_남는다() {
        Batch b = map(unwarranted(9));

        AuditEvent e = b.events().getFirst();
        assertThat(e.getWarrantId()).isZero();
        assertThat(e.getKernelSubjectId()).isNull();  // 0 은 "주체 없음"
        assertThat(e.getCgroupId()).isEqualTo(7594L);  // process 가 없으니 payload 에서

        UnwarrantedSession s = b.unwarrantedSessions().getFirst();
        assertThat(s.getNodeId()).isEqualTo(NODE);
        assertThat(s.getSeqEpoch()).isEqualTo(EPOCH);
        assertThat(s.getNodeSeq()).isEqualTo(9);
        assertThat(s.getObservedAt()).isEqualTo(T);
        assertThat(s.getLoginAccount()).isEqualTo("ec2-user");
        assertThat(s.getSourceAddress()).isEqualTo("10.0.0.5");
        assertThat(s.getCgroupId()).isEqualTo(7594);
        assertThat(s.getReason()).isEqualTo("NO_KEY");  // 접두사 REASON_ 없이
        assertThat(s.getSshKeyFingerprint()).isNull();  // proto 의 빈 문자열은 "없음"
    }

    @Test
    void 무영장_접속이_아니면_무영장세션은_생기지_않는다() {
        assertThat(map(base(1).setExec(ExecEvent.getDefaultInstance()).build()).unwarrantedSessions()).isEmpty();
    }

    @Test
    void 유실_구간이_옮겨지고_빠진_건수를_모르면_비워둔다() {
        AuditBatch batch = AuditBatch.newBuilder().setSeqEpoch(EPOCH)
                .addGaps(GapReport.newBuilder().setFromUnixNs(T_NS).setToUnixNs(T_NS + 5_000_000_000L)
                        .setDroppedCount(38).setDroppedCountKnown(true).setCause(GapReport.Cause.CAUSE_RINGBUF_OVERFLOW))
                .addGaps(GapReport.newBuilder().setFromUnixNs(T_NS).setToUnixNs(T_NS + 1)
                        .setDroppedCountKnown(false).setCause(GapReport.Cause.CAUSE_AGENT_DOWN))
                .build();

        var gaps = AuditProtoMapper.toBatch(NODE, batch).gaps();
        EventGap known = gaps.get(0);
        assertThat(known.getNodeId()).isEqualTo(NODE);
        assertThat(known.getFrom()).isEqualTo(T);
        assertThat(known.getTo()).isEqualTo(T.plusSeconds(5));
        assertThat(known.getDroppedCount()).isEqualTo(38L);
        assertThat(known.getCause()).isEqualTo("RINGBUF_OVERFLOW");  // 접두사 CAUSE_ 없이
        assertThat(gaps.get(1).getDroppedCount()).isNull();  // 모름 ≠ 0
    }

    @Test
    void 노드_자기소개가_노드_정보로_옮겨진다() {
        NodeHello hello = NodeHello.newBuilder()
                .setHostname("node-a").setKernelVersion("7.0.0-15-generic").setBpfLsmEnabled(true)
                .setAgentVersion("warrantd 0.1.0").setBootedAtUnixNs(T_NS)
                .addAttachedHooks(Hook.HOOK_SCHED_PROCESS_FORK).addAttachedHooks(Hook.HOOK_BPRM_CHECK_SECURITY)
                .build();

        assertThat(AuditProtoMapper.toReport(hello, EPOCH)).isEqualTo(new Report(
                "node-a", "7.0.0-15-generic", true, "warrantd 0.1.0",
                Set.of("HOOK_SCHED_PROCESS_FORK", "HOOK_BPRM_CHECK_SECURITY"), T, EPOCH));
    }

    @Test
    void 무슨_일인지_내용이_없는_기록은_거부된다() {
        assertThatThrownBy(() -> map(base(1).build())).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void 발생_시각이_없는_기록은_거부된다() {
        // 0 을 받으면 1970 년 파티션에 조용히 들어간다
        assertThatThrownBy(() -> map(base(1).setWallTsUnixNs(0).setExec(ExecEvent.getDefaultInstance()).build()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void 어디서_나온_기록인지_모르면_거부된다() {
        assertThatThrownBy(() -> map(base(1).setOrigin(Origin.ORIGIN_UNSPECIFIED)
                .setExec(ExecEvent.getDefaultInstance()).build()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void 쓰기_허용_횟수가_실려_오면_아직_저장할_곳이_없어_거부된다() {
        // 받고 넘어가면 ack 되어 노드가 지운다. 저장할 테이블이 생기기 전까지는 끊어서 드러낸다
        AuditBatch batch = AuditBatch.newBuilder().setSeqEpoch(EPOCH).setLastNodeSeq(1)
                .addEvents(unwarranted(1))
                .addWriteAggregates(WriteAggregate.newBuilder()
                        .setWarrantId(7).setBucketStartUnixNs(T_NS).setBucketNs(60_000_000_000L).setAllowedCount(12))
                .build();

        assertThatThrownBy(() -> AuditProtoMapper.toBatch(NODE, batch))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("write_aggregates");
    }
}
