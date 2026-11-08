package io.seswar.warrant.policy;

import io.seswar.warrant.policy.Policy;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface PolicyRepository extends JpaRepository<Policy, UUID> {
}
