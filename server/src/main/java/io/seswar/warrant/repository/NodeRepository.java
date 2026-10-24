package io.seswar.warrant.repository;

import io.seswar.warrant.domain.node.Node;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface NodeRepository extends JpaRepository<Node, UUID> {

    // Called by NodeRegistry when a node connects. The certificate fingerprint is the node's identity.
    Optional<Node> findByClientCertFingerprint(String clientCertFingerprint);

    // hostname 은 자기 신고라 여럿일 수 있다. 진단용.
    List<Node> findByHostname(String hostname);

    // Called by NodeRegistry.staleNodes. Nodes whose last heartbeat is older than the cutoff.
    List<Node> findByLastSeenAtBefore(Instant cutoff);
}
