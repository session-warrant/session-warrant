package io.seswar.warrant.application;

import io.seswar.warrant.domain.warrant.OnExpiry;
import io.seswar.warrant.domain.warrant.WarrantMode;

import java.time.Duration;
import java.util.List;
import java.util.UUID;

/** {@code duration} 기본값(warrant.default-duration)을 크게 잡지 말 것 — 넉넉한 영장은 상시 권한의 재발명이다(§03). */
public record IssueWarrantCommand(
        UUID subjectId,
        String reason,
        List<String> targetHosts,
        UUID policyId,
        Duration duration,
        WarrantMode mode,
        OnExpiry onExpiry,
        Duration graceWindow) {
}
