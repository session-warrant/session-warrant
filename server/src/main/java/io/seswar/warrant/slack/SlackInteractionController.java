package io.seswar.warrant.slack;

/**
 * Slack 버튼 콜백 수신.
 */
// @RestController @RequestMapping("/slack")
public class SlackInteractionController {

    /**
     * 반드시 먼저 할 일: <b>Slack 요청 서명 검증</b>({@code X-Slack-Signature}).
     * 이걸 빼면 아무나 승인 버튼을 눌러 영장을 발급시킬 수 있다 —
     * 승인 절차 전체가 장식이 된다.
     *
     * <p>그리고 Slack 사용자 → OIDC subject 매핑이 있어야 한다.
     * 매핑이 없는 사용자의 클릭은 거부한다. Slack 계정을 신원으로 그대로 믿지 않는다.
     */
    public Object onInteraction(/* String rawBody, HttpHeaders headers */) {
        // 1. 서명 검증 + 타임스탬프 재생 공격 방지(5분)
        // 2. action_id 파싱 → approve / reject / extend
        // 3. Slack user → Subject 매핑 확인, 자기 승인 금지 재확인
        // 4. ApprovalService 호출
        // 5. 3초 안에 200 을 돌려주고 실제 처리는 비동기 — 늦으면 Slack 이 재전송한다.
        //    재전송에 대비해 action 처리는 멱등이어야 한다 (중복 승인 = 중복 발급)
        throw new UnsupportedOperationException("미구현");
    }
}
