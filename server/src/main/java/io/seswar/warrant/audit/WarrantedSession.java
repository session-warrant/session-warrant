package io.seswar.warrant.audit;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

/** 영장이 맞아 cgroup 에 태그된 SSH 세션. 무영장 세션과 합치면 「조직 전체 SSH 접속 현황」(뷰 ssh_session)이 된다. */
@Entity
@Table(name = "warranted_session")
public class WarrantedSession {

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

    @Column(nullable = false)
    private long warrantId;

    private Integer kernelSubjectId;

    @Column(nullable = false)
    private String mode;

    private String loginAccount;

    private String sshKeyFingerprint;

    private String sourceAddress;

    @Column(nullable = false)
    private long cgroupId;

    protected WarrantedSession() {
    }

    // Called by AuditProtoMapper for each WarrantedSessionEvent in a batch.
    public static WarrantedSession of(UUID nodeId, long seqEpoch, long nodeSeq, Instant observedAt,
                                      long warrantId, Integer kernelSubjectId, String mode, String loginAccount,
                                      String sshKeyFingerprint, String sourceAddress, long cgroupId) {
        WarrantedSession s = new WarrantedSession();
        s.nodeId = nodeId;
        s.seqEpoch = seqEpoch;
        s.nodeSeq = nodeSeq;
        s.observedAt = observedAt;
        s.warrantId = warrantId;
        s.kernelSubjectId = kernelSubjectId;
        s.mode = mode;
        s.loginAccount = loginAccount;
        s.sshKeyFingerprint = sshKeyFingerprint;
        s.sourceAddress = sourceAddress;
        s.cgroupId = cgroupId;
        return s;
    }

    public UUID getId() { return id; }

    public UUID getNodeId() { return nodeId; }

    public long getSeqEpoch() { return seqEpoch; }

    public long getNodeSeq() { return nodeSeq; }

    public Instant getObservedAt() { return observedAt; }

    public long getWarrantId() { return warrantId; }

    public Integer getKernelSubjectId() { return kernelSubjectId; }

    public String getMode() { return mode; }

    public String getLoginAccount() { return loginAccount; }

    public String getSshKeyFingerprint() { return sshKeyFingerprint; }

    public String getSourceAddress() { return sourceAddress; }

    public long getCgroupId() { return cgroupId; }
}
