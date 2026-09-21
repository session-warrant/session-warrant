package io.seswar.warrant.repository;

/**
 * 현재 상태는 계보로부터 계산하는 뷰지만, 조회 성능을 위해 {@code warrant} 테이블에
 * 비정규화해 들고 있다. <b>계보가 원본이고 상태는 파생</b>이라는 방향을 뒤집지 말 것 —
 * 뒤집는 순간 "왜 이렇게 됐나"에 답할 수 없어진다.
 */
// @Repository
public interface WarrantRepository /* extends JpaRepository<Warrant, UUID> */ {

    // findByDisplayId(String)
    // findActiveByTargetHost(String)          — push 대상 해석
    // findActiveBySubjectId(UUID)             — 일괄 회수
    // findExpiringWithin(Duration)            — T-5분 연장 요청 트리거 (실제 감지는 warrantd 가 한다)
    // findAllActive()                         — 노드 재연결 시 resync
}
