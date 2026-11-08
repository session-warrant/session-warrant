package io.seswar.warrant.warrant;

/**
 * 계보 — <b>append-only</b>. update · delete 메서드를 만들지 않는다.
 * 만들어 두면 언젠가 누가 쓴다.
 */
// @Repository
public interface WarrantLineageRepository /* extends JpaRepository<WarrantLineage, UUID> */ {

    // findByWarrantIdOrderByOccurredAtAsc(UUID)
    // countByWarrantIdAndTypeIn(UUID, Collection<LineageType>)   — 자동 승인 횟수 계산
}
