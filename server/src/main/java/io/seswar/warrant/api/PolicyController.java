package io.seswar.warrant.api;

// @RestController @RequestMapping("/api/policies")
public class PolicyController {

    // GET  /api/policies
    // POST /api/policies
    // POST /api/policies/{id}/lint   — 저장 전에 조합 위험을 미리 보여준다

    /**
     * lint 결과를 <b>저장 전에</b> 돌려준다.
     * 실행 허용과 쓰기 허용을 따로 보면 안전을 보장할 수 없으므로(§04),
     * 콘솔이 두 목록을 한 화면에서 편집하고 그때마다 이 엔드포인트를 부르는 형태여야 한다.
     */
    public Object lint(/* PolicyRequest body */) {
        throw new UnsupportedOperationException("미구현");
    }
}
