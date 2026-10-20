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

/** 감사 레코드 한 건. 필드의 뜻과 제약은 server/README.md 「감사 엔티티」. */
@Entity
@Table(name = "audit_event")
public class AuditEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false)
    private Instant occurredAt;

    @Column(nullable = false)
    private UUID nodeId;

    private long seqEpoch;

    private long nodeSeq;

    private long warrantId;

    private Integer kernelSubjectId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AuditEventType type;

    @Convert(converter = VerdictConverter.class)
    @Column(nullable = false)
    private Verdict verdict;

    @Convert(converter = ModeConverter.class)
    private WarrantMode mode;

    @Convert(converter = TagSourceConverter.class)
    @Column(nullable = false)
    private TagSource tagSource;

    @Convert(converter = OriginConverter.class)
    @Column(nullable = false)
    private Origin origin;

    private Long pid;

    private Long cgroupId;

    private Integer uid;

    private Long deviceId;

    private Long inode;

    private String resolvedPath;

    private String argvTruncated;

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
