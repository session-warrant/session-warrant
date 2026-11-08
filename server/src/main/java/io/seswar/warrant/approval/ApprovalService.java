package io.seswar.warrant.approval;

import io.seswar.warrant.warrant.LineageType;
import io.seswar.warrant.warrant.Warrant;
import io.seswar.warrant.warrant.WarrantLineage;
import io.seswar.warrant.warrant.WarrantLineageRepository;
import io.seswar.warrant.warrant.WarrantRepository;
import io.seswar.warrant.warrant.WarrantSealer;
import io.seswar.warrant.warrant.WarrantState;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.ResponseStatus;

import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.UUID;

/**
 * 발급 신청의 승인 결정. 신청은 콘솔 승인 큐({@code /api/approvals})에 올라가고 다른 사람이 처리한다.
 * <b>자기 승인 금지는 여기서 집행한다</b> — 화면의 비활성 버튼은 집행이 아니다.
 * 서버는 알림을 보내지 않는다 — "대기 중인 요청" 경보는 Grafana 가 DB 를 직접 읽어 건다.
 *
 * <p>아직 없는 것: 연장 요청, 승인자 자격(팀 · 상급자), 화면에서 본 요청인지 확인(requestLineageId).
 * 같은 신청을 두 번 승인하면 상태가 이미 ISSUED 라 409 가 된다.
 */
@Service
@RequiredArgsConstructor
public class ApprovalService {

    private final WarrantRepository warrants;
    private final WarrantLineageRepository lineage;
    private final WarrantSealer sealer;
    private final Clock clock;

    @ResponseStatus(HttpStatus.FORBIDDEN)
    public static class SelfApprovalException extends RuntimeException {
        SelfApprovalException(String displayId) {
            super("cannot decide your own request " + displayId);
        }
    }

    @Transactional(readOnly = true)
    public List<Warrant> queue() {
        return warrants.findByStateOrderByWarrantIdAsc(WarrantState.REQUESTED);
    }

    /** 승인 → 서명. push 는 커밋 뒤 호출자가 한다. */
    @Transactional
    public Warrant approve(UUID warrantId, UUID approverId) {
        Warrant w = decidable(warrantId, approverId);
        Duration requested = lineage.findByWarrantIdOrderByOccurredAtAsc(w.getId()).stream()
                .filter(l -> l.getType() == LineageType.REQUESTED).findFirst()
                .map(WarrantLineage::delta)
                .orElseThrow(() -> new IllegalStateException("warrant " + w.getDisplayId() + " has no REQUESTED line"));
        w.approve(clock.instant(), requested);
        sealer.seal(w);
        lineage.save(WarrantLineage.of(w.getId(), LineageType.ISSUED, clock.instant(), approverId, null,
                requested, w.getExpiresAt()));
        return w;
    }

    @Transactional
    public Warrant reject(UUID warrantId, UUID approverId, String reason) {
        if (reason == null || reason.isBlank()) {
            throw new IllegalArgumentException("a rejection needs a reason");
        }
        Warrant w = decidable(warrantId, approverId);
        w.reject();
        lineage.save(WarrantLineage.of(w.getId(), LineageType.REJECTED, clock.instant(), approverId, reason.trim(),
                null, null));
        return w;
    }

    // The requester is the warrant's subject; nobody decides their own request.
    private Warrant decidable(UUID warrantId, UUID approverId) {
        Warrant w = warrants.findById(warrantId)
                .orElseThrow(() -> new IllegalArgumentException("unknown warrant " + warrantId));
        if (w.getSubjectId().equals(approverId)) {
            throw new SelfApprovalException(w.getDisplayId());
        }
        if (w.getState() != WarrantState.REQUESTED) {
            throw new IllegalStateException("warrant " + w.getDisplayId() + " is " + w.getState() + ", not REQUESTED");
        }
        return w;
    }
}
