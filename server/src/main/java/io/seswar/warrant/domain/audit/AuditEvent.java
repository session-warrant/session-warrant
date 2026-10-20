package io.seswar.warrant.domain.audit;

import io.seswar.warrant.domain.audit.AuditEnumConverters.ModeConverter;
import io.seswar.warrant.domain.audit.AuditEnumConverters.OriginConverter;
import io.seswar.warrant.domain.audit.AuditEnumConverters.TagSourceConverter;
import io.seswar.warrant.domain.audit.AuditEnumConverters.VerdictConverter;
import io.seswar.warrant.domain.warrant.WarrantMode;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

/**
 * 감사 레코드 한 건. 커널 ringbuf → warrantd → gRPC 로 여기 도착한다.
 *
 * <p>남는 것(§14) — 실행된 모든 프로세스, 자원에 손댄 순간.
 * 안 남는 것 — 셸 빌트인({@code cd}), 인터프리터 내부 로직, 파일 읽기, 터미널 입력.
 */
@Entity
@Table(name = "audit_event")  // PARTITION BY RANGE (occurred_at). DB 의 PK 는 (id, occurred_at)
public class AuditEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false)
    private Instant occurredAt;

    /** mTLS 인증서로 찾은 노드. 노드가 신고한 hostname 이 아니다. */
    @Column(nullable = false)
    private UUID nodeId;

    /**
     * 멱등 키는 {@code (nodeId, seqEpoch, nodeSeq)} — 재전송은 ON CONFLICT DO NOTHING.
     * seqEpoch 가 없으면 bbolt 초기화 뒤 nodeSeq 가 1 로 돌아가 새 이벤트가 중복으로 버려진다.
     */
    private long seqEpoch;

    private long nodeSeq;

    /**
     * 커널이 들고 있던 u64 (proto {@code warrant_id}) — {@code Warrant.warrantId} 와 조인한다.
     * 0 이면 영장 없는 프로세스. 그 자체가 조사 대상이다.
     */
    private long warrantId;

    /** 커널이 들고 있던 u32. 조회 시점에 사람 이름으로 조인된다. */
    private Integer kernelSubjectId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AuditEventType type;

    @Convert(converter = VerdictConverter.class)
    @Column(nullable = false)
    private Verdict verdict;

    /** WOULD_DENY 가 OBSERVE 인지 DRYRUN 인지 가른다. */
    @Convert(converter = ModeConverter.class)
    private WarrantMode mode;

    /** TASK 면 cgroup 을 벗어난 프로세스를 2차 방어선(fork 전파)이 잡은 것이다. */
    @Convert(converter = TagSourceConverter.class)
    @Column(nullable = false)
    private TagSource tagSource;

    /** lsm 과 kprobe 미러가 같은 입력에 다른 verdict 를 내면 버그다(§15). */
    @Convert(converter = OriginConverter.class)
    @Column(nullable = false)
    private Origin origin;

    // 이하는 훅에 따라 비어 있다 (예: 무영장 세션에는 inode 가 없다). 그래서 래퍼 타입.
    private Long pid;

    private Long cgroupId;

    /** sudo 뒤의 uid. 신원이 아니라 정황 정보다 — 신원은 warrantId 쪽에 있다. */
    private Integer uid;

    /** 커널이 실제로 연 파일의 {@code (dev, ino)}. <b>신뢰의 근거는 이것이다.</b> */
    private Long deviceId;

    private Long inode;

    /** 해석된 경로. 리포트 가독성을 위한 참고 정보이며 증거로 쓰지 않는다. */
    private String resolvedPath;

    /**
     * 명령줄 인자. <b>1급 증거가 아니다</b>(§14) — BPF 스택 제약으로 잘리고
     * {@code exec -a} 한 줄이면 argv[0] 이 위조된다.
     */
    private String argvTruncated;

    /** CONNECT · UDP_SEND 일 때의 목적지. AF_UNIX 면 sun_path. */
    private String destination;

    protected AuditEvent() {
    }

    // Called by the gRPC layer to turn one proto AuditEvent into an entity.
    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private final AuditEvent e = new AuditEvent();

        public Builder occurredAt(Instant v) { e.occurredAt = v; return this; }
        public Builder nodeId(UUID v) { e.nodeId = v; return this; }
        public Builder seqEpoch(long v) { e.seqEpoch = v; return this; }
        public Builder nodeSeq(long v) { e.nodeSeq = v; return this; }
        public Builder warrantId(long v) { e.warrantId = v; return this; }
        public Builder kernelSubjectId(Integer v) { e.kernelSubjectId = v; return this; }
        public Builder type(AuditEventType v) { e.type = v; return this; }
        public Builder verdict(Verdict v) { e.verdict = v; return this; }
        public Builder mode(WarrantMode v) { e.mode = v; return this; }
        public Builder tagSource(TagSource v) { e.tagSource = v; return this; }
        public Builder origin(Origin v) { e.origin = v; return this; }
        public Builder pid(Long v) { e.pid = v; return this; }
        public Builder cgroupId(Long v) { e.cgroupId = v; return this; }
        public Builder uid(Integer v) { e.uid = v; return this; }
        public Builder deviceId(Long v) { e.deviceId = v; return this; }
        public Builder inode(Long v) { e.inode = v; return this; }
        public Builder resolvedPath(String v) { e.resolvedPath = v; return this; }
        public Builder argvTruncated(String v) { e.argvTruncated = v; return this; }
        public Builder destination(String v) { e.destination = v; return this; }

        public AuditEvent build() {
            return e;
        }
    }

    // ---------------------------------------------------------------- getters

    public UUID getId() { return id; }

    public Instant getOccurredAt() { return occurredAt; }

    public UUID getNodeId() { return nodeId; }

    public long getSeqEpoch() { return seqEpoch; }

    public long getNodeSeq() { return nodeSeq; }

    public long getWarrantId() { return warrantId; }

    public Integer getKernelSubjectId() { return kernelSubjectId; }

    public AuditEventType getType() { return type; }

    public Verdict getVerdict() { return verdict; }

    public WarrantMode getMode() { return mode; }

    public TagSource getTagSource() { return tagSource; }

    public Origin getOrigin() { return origin; }

    public Long getPid() { return pid; }

    public Long getCgroupId() { return cgroupId; }

    public Integer getUid() { return uid; }

    public Long getDeviceId() { return deviceId; }

    public Long getInode() { return inode; }

    public String getResolvedPath() { return resolvedPath; }

    public String getArgvTruncated() { return argvTruncated; }

    public String getDestination() { return destination; }

    /** 정수값은 proto {@code TagSource} 와 같다. */
    public enum TagSource {
        NONE(0), CGROUP(1), TASK(2);

        private final int wireValue;

        TagSource(int wireValue) {
            this.wireValue = wireValue;
        }

        public int wireValue() {
            return wireValue;
        }

        public static TagSource fromWire(int value) {
            for (TagSource t : values()) {
                if (t.wireValue == value) {
                    return t;
                }
            }
            throw new IllegalArgumentException("unknown TagSource wire value: " + value);
        }
    }

    /** 정수값은 proto {@code Origin} 과 같다. 0 은 UNSPECIFIED 라 저장하지 않는다. */
    public enum Origin {
        LSM(1), KPROBE(2), AGENT(3);

        private final int wireValue;

        Origin(int wireValue) {
            this.wireValue = wireValue;
        }

        public int wireValue() {
            return wireValue;
        }

        public static Origin fromWire(int value) {
            for (Origin o : values()) {
                if (o.wireValue == value) {
                    return o;
                }
            }
            throw new IllegalArgumentException("unknown Origin wire value: " + value);
        }
    }
}
