package io.seswar.warrant.audit;

import io.seswar.warrant.audit.AuditEnumConverters.OriginConverter;
import io.seswar.warrant.audit.AuditEnumConverters.TagSourceConverter;
import io.seswar.warrant.audit.AuditEnumConverters.VerdictConverter;
import io.seswar.warrant.warrant.WarrantMode;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.UUID;

/** 감사 레코드 한 건. 필드의 뜻과 제약은 server/README.md 「감사 엔티티」. */
@Entity
@Table(name = "audit_event")
@Getter
@Builder
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
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

    @Convert(converter = WarrantMode.Converter.class)
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

    /** proto Hook 번호. type 만으로는 unlink · rename, 자기보호의 어느 훅인지 모른다. 무영장 세션(HOOK_AGENT)은 100. */
    private Short hook;

    /** 프로세스 이름. 16바이트로 잘리고 위조 가능한 참고 정보 — 증거는 (deviceId, inode). */
    private String comm;

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
