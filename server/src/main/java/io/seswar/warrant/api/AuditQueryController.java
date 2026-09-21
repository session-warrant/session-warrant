package io.seswar.warrant.api;

/**
 * 감사 조회. 대시보드는 Grafana 가 맡고, 여기 REST 는 Grafana 로 표현하기 어려운
 * <b>단건 추적</b>(영장 하나의 전체 행적)을 담당한다.
 */
// @RestController @RequestMapping("/api/audit")
public class AuditQueryController {

    // GET /api/audit/events?warrantId=&subject=&node=&from=&to=&type=&verdict=
    // GET /api/audit/gaps?node=&from=&to=          — 유실 구간. 숨기지 않는다
    // GET /api/audit/unwarranted?from=&to=         — STEP 2 리포트

    /**
     * 이벤트 조회. 응답 정렬 원칙:
     * <b>inode 기준 실제 실행 파일을 앞세우고 argv 는 참고 정보로 뒤에 붙인다</b>(§14).
     * argv 를 주 필드로 렌더링하면 위조 가능한 값을 1급 증거로 보여주는 셈이 된다.
     */
    public Object events(/* AuditQuery query */) {
        throw new UnsupportedOperationException("미구현");
    }

    /**
     * 유실 구간 조회. 이벤트 목록과 <b>같은 화면</b>에 겹쳐 보여야 한다.
     * 별도 탭으로 빼면 아무도 안 보고, 구멍이 없는 것처럼 읽힌다.
     */
    public Object gaps(/* UUID nodeId, Instant from, Instant to */) {
        throw new UnsupportedOperationException("미구현");
    }
}
