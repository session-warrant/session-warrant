package io.seswar.warrant.application;

import java.util.UUID;

/**
 * 발급 · 연장 요청의 승인 결정. 요청은 콘솔 승인 큐({@code /api/approvals})에 올라가고
 * 승인자가 거기서 처리한다. 서버는 외부 채널로 알림을 보내지 않는다 —
 * "대기 중인 요청" 경보는 Grafana 가 DB 를 직접 읽어 건다.
 */
// @Service
public class ApprovalService {

    /** 승인 큐에 올린다. 노드로는 아무것도 내려가지 않는다. */
    public void submitForApproval(UUID warrantId, UUID requesterId) {
        // 1. 승인자 후보 결정 — 대상 호스트의 소유 팀 · 요청자의 상급자 등
        // 2. 요청자 외에 승인 가능한 사람이 없으면 여기서 거부한다 (큐에 영원히 남는 요청을 만들지 않는다)
        throw new UnsupportedOperationException("미구현");
    }

    /**
     * 발급 대기면 발급, 연장 요청이면 연장. {@code requestLineageId} 가 지금 열린 요청과 다르면 거부(멱등).
     */
    public void approve(UUID warrantId, UUID requestLineageId, UUID approverId, String reason) {
        // 1. 승인자 == 요청자 면 거부 (자기 승인 금지). 연장 요청은 영장 주체 본인도 승인할 수 없다
        // 2. APPROVER 권한 · 대상 호스트 승인 범위 확인
        // 3. 발급 대기 → WarrantIssuanceService.issue(), 연장 요청 → WarrantExtensionService.extend()
        throw new UnsupportedOperationException("미구현");
    }

    public void reject(UUID warrantId, UUID requestLineageId, UUID approverId, String reason) {
        // 발급 대기 → lineage += REJECTED, state = REJECTED
        // 연장 요청 → lineage += EXTENSION_DENIED. 영장은 원래 만료 시각대로 간다
        throw new UnsupportedOperationException("미구현");
    }

    /**
     * break-glass — 긴급 상황용 영장(§17).
     *
     * <p>오프라인 검증이 가능한 로컬 서명 영장이며, 정의상 §16 의 자기보호 제한까지 풀 수 있다.
     * 따라서 <b>발급과 사용 모두 최고 등급 경보 대상</b>이고 전 구간이 기록된다.
     *
     * <p>자기를 고치러 오는 사람을 잠그면 안 되므로 승인 절차로 막지 않는다 —
     * 사전 승인이 아니라 사후 추적으로 통제한다.
     */
    public void issueBreakGlass(UUID subjectId, String reason, String targetHost) {
        throw new UnsupportedOperationException("미구현");
    }
}
