package io.seswar.warrant.warrant;

import org.springframework.data.repository.Repository;

import java.util.List;
import java.util.UUID;

/**
 * 계보 — <b>append-only</b>. update · delete 메서드를 만들지 않는다.
 * 만들어 두면 언젠가 누가 쓴다. 그래서 JpaRepository 가 아니라 필요한 메서드만 연다.
 */
public interface WarrantLineageRepository extends Repository<WarrantLineage, UUID> {

    WarrantLineage save(WarrantLineage line);

    List<WarrantLineage> findByWarrantIdOrderByOccurredAtAsc(UUID warrantId);
}
