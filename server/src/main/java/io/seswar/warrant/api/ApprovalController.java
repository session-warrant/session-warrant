package io.seswar.warrant.api;

/**
 * 승인 큐 — 콘솔에서 신청 · 승인한다. 외부 메신저 연동은 두지 않는다.
 *
 * <p>큐의 한 항목은 "결정을 기다리는 영장 하나"다. 발급 대기(state=REQUESTED)와
 * 열린 연장 요청(계보 끝이 EXTENSION_REQUESTED)은 한 영장에 동시에 생길 수 없으므로
 * 영장 id 하나로 항목이 정해진다.
 */
// @RestController @RequestMapping("/api/approvals")
public class ApprovalController {

    // GET  /api/approvals?kind=ISSUE|EXTENSION      승인 큐. 본인 요청도 보이되 approvable=false 로 내린다
    // POST /api/approvals/{warrantId}/approve       { requestLineageId, reason }
    // POST /api/approvals/{warrantId}/reject        { requestLineageId, reason }  — 사유 필수
    //
    // 승인자 = OIDC 로그인 주체. 본문에 승인자 id 를 받지 않는다.

    /**
     * 큐 항목에 들어갈 것: 주체 · 사유(티켓 번호) · 대상 호스트 · 기간 · 정책 요약 · lint 경고.
     * 연장 요청이면 <b>무슨 작업이 돌고 있어서</b> 연장이 필요한지(detected_workload)도 함께 보인다.
     */
    public Object queue(/* ApprovalKind kind, Authentication auth */) {
        throw new UnsupportedOperationException("미구현");
    }

    /**
     * {@code requestLineageId} 는 승인자가 화면에서 본 요청이다. 그 사이 요청이 바뀌었거나
     * 이미 처리됐으면 409 — 이중 클릭 · 두 승인자 동시 승인이 중복 발급이 되지 않는다.
     */
    public Object approve(/* UUID warrantId, DecisionRequest body, Authentication auth */) {
        // 1. auth → Subject (oidcSubject). 매핑이 없으면 403
        // 2. ApprovalService.approve() — 자기 승인 금지는 서비스가 판정한다. 화면의 비활성 버튼은 집행이 아니다
        throw new UnsupportedOperationException("미구현");
    }

    public Object reject(/* UUID warrantId, DecisionRequest body, Authentication auth */) {
        throw new UnsupportedOperationException("미구현");
    }
}
