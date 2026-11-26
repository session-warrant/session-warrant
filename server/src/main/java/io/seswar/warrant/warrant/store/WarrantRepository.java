package io.seswar.warrant.warrant.store;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * 현재 상태는 계보로부터 계산하는 뷰지만, 조회 성능을 위해 {@code warrant} 테이블에
 * 비정규화해 들고 있다. <b>계보가 원본이고 상태는 파생</b>이라는 방향을 뒤집지 말 것 —
 * 뒤집는 순간 "왜 이렇게 됐나"에 답할 수 없어진다.
 */
public interface WarrantRepository extends JpaRepository<Warrant, UUID> {

    // Called by WarrantPushGrpcService when a node subscribes: the active set it gets before ResyncComplete.
    // Only ISSUED: a REQUESTED warrant has no signature yet and must never reach a node.
    @Query("select w from Warrant w join w.targetHosts h "
            + "where h = :host and w.state = :issued and w.revoked = false and w.expiresAt > :now order by w.warrantId")
    List<Warrant> findActiveForHostInState(@Param("host") String host, @Param("now") Instant now,
                                           @Param("issued") WarrantState issued);

    default List<Warrant> findActiveForHost(String host, Instant now) {
        return findActiveForHostInState(host, now, WarrantState.ISSUED);
    }

    // Called by ApprovalController: the approval queue, oldest first.
    List<Warrant> findByStateOrderByWarrantIdAsc(WarrantState state);

    List<Warrant> findAllByOrderByIssuedAtDesc();

    // Called by WarrantExtensionService. The row lock makes two approvals of one extension request, or an
    // extension racing a revocation, take turns instead of both reading the same open request.
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<Warrant> findLockedById(UUID id);

    // Called by WarrantExtensionService for a node's request, which names the kernel id.
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<Warrant> findLockedByWarrantId(long warrantId);
}
