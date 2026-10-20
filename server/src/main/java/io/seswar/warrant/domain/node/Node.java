package io.seswar.warrant.domain.node;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

/** 영장을 집행하는 호스트. warrantd 한 대가 한 노드다. 필드의 뜻과 제약은 server/README.md 「노드」. */
@Entity
@Table(name = "node")
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
}
