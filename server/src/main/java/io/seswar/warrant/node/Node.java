package io.seswar.warrant.node;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

/** 영장을 집행하는 호스트. warrantd 한 대가 한 노드다. 필드의 뜻과 제약은 server/README.md 「노드」. */
@Entity
@Table(name = "node")
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class Node {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, unique = true)
    private String clientCertFingerprint;

    @Column(nullable = false)
    private String hostname;

    private String kernelVersion;

    private boolean bpfLsmEnabled;

    private String agentVersion;

    @JdbcTypeCode(SqlTypes.ARRAY)
    @Column(nullable = false)
    private Set<String> attachedHooks;

    private Long currentSeqEpoch;

    private Instant lastSeenAt;

    private Instant bootedAt;

    /** 폐기 시각(V8). null 이 아니면 이 신원으로는 어떤 gRPC 호출도 받지 않는다. 되돌리지 않는다. */
    private Instant revokedAt;

    /** 폐기한 사람(주체 id). */
    private UUID revokedBy;

    private String revokeReason;

    // Called by NodeRegistry.register when a known node reconnects. Overwrites what the node reports about itself.
    // Called by NodeRegistry when a node first connects with a certificate: its identity becomes the certificate.
    void identifyBy(String certificateIdentity) {
        this.clientCertFingerprint = certificateIdentity;
    }

    public void refresh(String hostname, String kernelVersion, boolean bpfLsmEnabled, String agentVersion,
                        Set<String> attachedHooks, Instant bootedAt, long seqEpoch, Instant now) {
        this.hostname = hostname;
        this.kernelVersion = kernelVersion;
        this.bpfLsmEnabled = bpfLsmEnabled;
        this.agentVersion = agentVersion;
        this.attachedHooks = Set.copyOf(attachedHooks);
        this.bootedAt = bootedAt;
        this.currentSeqEpoch = seqEpoch;
        this.lastSeenAt = now;
    }

    // Called by NodeRegistry.heartbeat.
    public void touch(Instant now) {
        this.lastSeenAt = now;
    }

    public boolean isRevoked() {
        return revokedAt != null;
    }

    // Called by NodeRevocationService.revoke.
    void revoke(Instant now, UUID by, String reason) {
        if (revokedAt != null) {
            throw new IllegalStateException("node " + hostname + " was already revoked at " + revokedAt);
        }
        this.revokedAt = now;
        this.revokedBy = by;
        this.revokeReason = reason;
    }
}
