package io.seswar.warrant;

/**
 * 통합 테스트 골격. PostgreSQL 을 Testcontainers 로 띄워 돌린다.
 *
 * <h3>여기서 반드시 다뤄야 할 케이스</h3>
 * <ul>
 *   <li>연장 누적 상한 — 사람 승인이든 자동이든 상한을 넘지 못한다</li>
 *   <li>쓰기 규칙이 있는 영장은 자동 승인되지 않는다</li>
 *   <li>서명은 protobuf 바이트에 대해 이뤄지고, 역직렬화 후 재직렬화하면 검증이 깨진다는 것을 명시적으로 확인</li>
 *   <li>{@code on_expiry=SESSION_ONLY_GRACE} 인데 grace 가 없으면 발급이 거부된다</li>
 *   <li>정책 lint — systemctl 실행 허용 + /etc/systemd/system 쓰기 허용 조합이 경고된다</li>
 *   <li>자기보호 6종을 여는 정책은 발급이 거부된다 (break-glass 제외)</li>
 *   <li>감사 이벤트 재전송이 멱등하다</li>
 *   <li>자기 승인 금지</li>
 * </ul>
 */
// @SpringBootTest @Testcontainers
class WarrantServerApplicationTests {

    // @Test void contextLoads() {}
}
