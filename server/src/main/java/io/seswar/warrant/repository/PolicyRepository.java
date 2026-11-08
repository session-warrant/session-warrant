package io.seswar.warrant.repository;

import io.seswar.warrant.domain.policy.Policy;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface PolicyRepository extends JpaRepository<Policy, UUID> {
}
