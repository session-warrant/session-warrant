package io.seswar.warrant.application;

import java.util.UUID;

// @Service
public class ApprovalService {

    /** 승인 요청 전달. 채널은 Slack 이 기본이고, 실패 시 이메일로 폴백한다. */
    public void submitForApproval(UUID warrantId, UUID requesterId) {
        // 1. 승인자 결정 — 대상 호스트의 소유 팀 · 요청자의 상급자 등
        // 2. 요청자 == 승인자 인 경우를 막는다 (자기 승인 금지)
        // 3. SlackApprovalNotifier.notifyNew()
        throw new UnsupportedOperationException("미구현");
    }

    public void approve(UUID warrantId, UUID approverId) {
        // 승인 권한 확인 → WarrantIssuanceService.issue()
        throw new UnsupportedOperationException("미구현");
    }

    public void reject(UUID warrantId, UUID approverId, String reason) {
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
