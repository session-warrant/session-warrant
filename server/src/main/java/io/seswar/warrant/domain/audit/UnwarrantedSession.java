package io.seswar.warrant.domain.audit;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

/** 영장 없이 성립한 SSH 세션(§07 STEP 2). */
@Entity
@Table(name = "unwarranted_session")
public class UnwarrantedSession {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false)
    private UUID nodeId;

    /** 이 세션을 실어 온 감사 이벤트의 키. (nodeId, seqEpoch, nodeSeq) 가 재전송 멱등 키다(V2). */
    @Column(nullable = false)
    private long seqEpoch;

    @Column(nullable = false)
    private long nodeSeq;

    @Column(nullable = false)
    private Instant observedAt;

    private String loginAccount;

    /** 공개키 지문({@code SHA256:...}). 비어 있으면 NO_KEY. <b>이 값으로 사람을 역추적한다.</b> */
    private String sshKeyFingerprint;

    private String sourceAddress;

    @Column(nullable = false)
    private long cgroupId;

    /**
     * proto {@code UnwarrantedSessionEvent.Reason}: NO_WARRANT · NO_KEY · KEY_MISMATCH ·
     * AGENT_UNREACHED · CENTRAL_STALE · PAM_ABSENT.
     */
    @Column(nullable = false)
    private String reason;

    /**
     * 이 세션이 실제로 무엇을 했는지 — 연결된 감사 이벤트 수.
     * "무영장 세션이 몇 건 있었다"보다 "무영장 세션이 무엇을 했다"가 훨씬 강한 자료다.
     */
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
