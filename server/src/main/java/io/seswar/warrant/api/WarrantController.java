package io.seswar.warrant.api;

// @RestController @RequestMapping("/api/warrants")
public class WarrantController {

    // POST   /api/warrants                  발급 요청 (승인 전)
    // GET    /api/warrants/{id}             단건 — 계보 포함
    // GET    /api/warrants?subject=&state=  목록
    // POST   /api/warrants/{id}/extend      연장 요청 또는 승인
    // DELETE /api/warrants/{id}             회수
    //
    // 주의: 만료를 여기서 "실행"하는 엔드포인트를 만들지 말 것.
    // 만료는 커널이 시각 비교로 스스로 발효시킨다(§05). 서버가 만료를 선언하는 API 를 두면
    // "서버가 안 눌러서 아직 안 만료됐다"는 오해와 실제 버그가 동시에 생긴다.

    public Object request(/* IssueWarrantRequest body, Authentication auth */) {
        throw new UnsupportedOperationException("미구현");
    }

    /**
     * 단건 조회 — <b>계보가 본체다</b>.
     * 감사에서 "30분짜리 작업이 왜 90분이었나"에 이 응답 하나로 답할 수 있어야 한다(§03).
     */
    public Object get(/* UUID id */) {
        throw new UnsupportedOperationException("미구현");
    }

    public Object extend(/* UUID id, ExtendRequest body */) {
        throw new UnsupportedOperationException("미구현");
    }

    public void revoke(/* UUID id, RevokeRequest body */) {
        throw new UnsupportedOperationException("미구현");
    }
}
