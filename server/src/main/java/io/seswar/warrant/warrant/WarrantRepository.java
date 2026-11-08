package io.seswar.warrant.warrant;

import io.seswar.warrant.warrant.Warrant;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * 현재 상태는 계보로부터 계산하는 뷰지만, 조회 성능을 위해 {@code warrant} 테이블에
 * 비정규화해 들고 있다. <b>계보가 원본이고 상태는 파생</b>이라는 방향을 뒤집지 말 것 —
 * 뒤집는 순간 "왜 이렇게 됐나"에 답할 수 없어진다.
 */
public interface WarrantRepository extends JpaRepository<Warrant, UUID> {

    // Called by WarrantPushGrpcService when a node subscribes: the active set it gets before ResyncComplete.
    @Query("select w from Warrant w join w.targetHosts h "
            + "where h = :host and w.revoked = false and w.expiresAt > :now order by w.warrantId")
    List<Warrant> findActiveForHost(@Param("host") String host, @Param("now") Instant now);

    List<Warrant> findAllByOrderByIssuedAtDesc();
}
