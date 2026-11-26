package io.seswar.warrant.warrant.api;

import io.seswar.warrant.warrant.store.LineageType;
import io.seswar.warrant.warrant.store.OnExpiry;
import io.seswar.warrant.warrant.store.Warrant;
import io.seswar.warrant.warrant.store.WarrantLineage;
import io.seswar.warrant.warrant.store.WarrantLineageRepository;
import io.seswar.warrant.warrant.store.WarrantMode;
import io.seswar.warrant.warrant.store.WarrantState;
import io.seswar.warrant.identity.Subject;
import io.seswar.warrant.identity.SubjectRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

/** 영장 응답 모양. WarrantController 와 ApprovalController 가 같은 모양을 내린다. 계보가 본체다(§03). */
@Component
@RequiredArgsConstructor
public class WarrantViews {

    private final WarrantLineageRepository lineage;
    private final SubjectRepository subjects;

    /** basis: 사람 없이 내린 결정(자동 연장 · warrantd 의 요청)의 근거. */
    public record LineView(LineageType type, Instant at, String actor, String reason, String basis, Long deltaSeconds) {
    }

    public record WarrantView(UUID id, long warrantId, String displayId, int revision, WarrantState state,
                              UUID subjectId, String loginAccount, List<String> sshKeyFingerprints,
                              List<String> targetHosts, UUID policyId, String reason, WarrantMode mode,
                              OnExpiry onExpiry, Instant issuedAt, Instant expiresAt, boolean revoked,
                              Long durationSeconds, List<LineView> lineage) {
    }

    // One lineage query per warrant — fine for a console list, not for a report.
    public WarrantView of(Warrant w) {
        List<WarrantLineage> lines = lineage.findByWarrantIdOrderByOccurredAtAsc(w.getId());
        Map<UUID, String> who = subjects.findAllById(lines.stream().map(WarrantLineage::getActorId)
                        .filter(java.util.Objects::nonNull).distinct().toList()).stream()
                .collect(Collectors.toMap(Subject::getId, Subject::getPrincipal));
        Long duration = lines.stream().filter(l -> l.getType() == LineageType.REQUESTED).findFirst()
                .map(WarrantLineage::getDeltaSeconds)
                .orElse(w.getIssuedAt() == null ? null : w.getExpiresAt().getEpochSecond() - w.getIssuedAt().getEpochSecond());
        return new WarrantView(w.getId(), w.getWarrantId(), w.getDisplayId(), w.getRevision(), w.getState(),
                w.getSubjectId(), w.getLoginAccount(), w.getSshKeyFingerprints().stream().sorted().toList(),
                w.getTargetHosts().stream().sorted().toList(), w.getPolicyId(), w.getReason(), w.getMode(),
                w.getOnExpiry(), w.getIssuedAt(), w.getExpiresAt(), w.isRevoked(), duration,
                lines.stream().map(l -> new LineView(l.getType(), l.getOccurredAt(), who.get(l.getActorId()),
                        l.getReason(), l.getBasis(), l.getDeltaSeconds())).toList());
    }
}
