package io.seswar.warrant.slack;

import java.util.UUID;

/**
 * Slack Block Kit 승인 알림. 승인이 버튼 하나로 끝나야 짧은 기본 발급 기간이 굴러간다 —
 * 연장이 비싸면 사람들은 처음부터 넉넉한 영장을 요구한다(§03).
 */
// @Component
public class SlackApprovalNotifier {

    /**
     * 신규 발급 요청 알림. 카드에 들어갈 것:
     * 주체 · 사유(티켓 번호) · 대상 호스트 · 기간 · 정책 요약 · lint 경고 · [승인][반려] 버튼.
     */
    public void notifyNew(UUID warrantId) {
        throw new UnsupportedOperationException("미구현");
    }

    /**
     * 연장 요청 알림. T-5분에 warrantd 가 진행 중 작업을 감지해 자동 생성한 요청이 여기로 온다.
     * <b>무슨 작업이 돌고 있어서</b> 연장이 필요한지 함께 보여야 승인자가 판단할 수 있다.
     */
    public void notifyExtensionRequested(UUID warrantId, String detectedWorkload) {
        throw new UnsupportedOperationException("미구현");
    }

    /** 유예 진입 알림 — "김개발 로그아웃, 잡 2개 유예 실행 중"(§03 안전장치 ③). */
    public void notifyGraceEntered(UUID warrantId, int survivingJobs) {
        throw new UnsupportedOperationException("미구현");
    }

    /** break-glass 사용 · 자기보호 훅 히트 — <b>최고 등급 경보</b>. */
    public void alertCritical(String title, String detail) {
        throw new UnsupportedOperationException("미구현");
    }
}
