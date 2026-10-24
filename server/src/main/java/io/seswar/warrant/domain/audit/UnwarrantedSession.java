package io.seswar.warrant.domain.audit;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

/** 영장 없이 성립한 SSH 세션(§07 STEP 2). 필드의 뜻과 제약은 server/README.md 「감사 엔티티」. */
@Entity
@Table(name = "unwarranted_session")
public class UnwarrantedSession {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false)
    private UUID nodeId;

    @Column(nullable = false)
    private long seqEpoch;

    @Column(nullable = false)
    private long nodeSeq;

    @Column(nullable = false)
    private Instant observedAt;

    private String loginAccount;

    private String sshKeyFingerprint;

    private String sourceAddress;

    @Column(nullable = false)
    private long cgroupId;

    @Column(nullable = false)
    private String reason;

    @Column(nullable = false)
    private long observedEventCount;

    protected UnwarrantedSession() {
    }

    // Called by the gRPC layer for each UnwarrantedSessionEvent in a batch.
    public static UnwarrantedSession of(UUID nodeId, long seqEpoch, long nodeSeq, Instant observedAt,
                                        String loginAccount, String sshKeyFingerprint, String sourceAddress,
                                        long cgroupId, String reason) {
        UnwarrantedSession u = new UnwarrantedSession();
        u.nodeId = nodeId;
        u.seqEpoch = seqEpoch;
        u.nodeSeq = nodeSeq;
        u.observedAt = observedAt;
        u.loginAccount = loginAccount;
        u.sshKeyFingerprint = sshKeyFingerprint;
        u.sourceAddress = sourceAddress;
        u.cgroupId = cgroupId;
        u.reason = reason;
        return u;
    }

    public UUID getId() { return id; }

    public UUID getNodeId() { return nodeId; }

    public long getSeqEpoch() { return seqEpoch; }

    public long getNodeSeq() { return nodeSeq; }

    public Instant getObservedAt() { return observedAt; }

    public String getLoginAccount() { return loginAccount; }

    public String getSshKeyFingerprint() { return sshKeyFingerprint; }

    public String getSourceAddress() { return sourceAddress; }

    public long getCgroupId() { return cgroupId; }

    public String getReason() { return reason; }

    public long getObservedEventCount() { return observedEventCount; }
}
