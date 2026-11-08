package io.seswar.warrant.warrant;

import io.seswar.warrant.warrant.Warrant;
import io.seswar.warrant.warrant.WarrantRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

/**
 * 회수. 연장과 같은 경로(새 revision push)이고, 커널에서는 {@code warrants[id].revoked = 1}
 * 한 바이트로 즉시 발효된다(§03, §05). DB 먼저 — push 가 실패해도 취소 사실은 남아야 한다.
 * push 는 커밋 뒤 호출자가 한다. 스트림이 끊긴 노드는 재연결 때 활성 집합에서 빠진 것으로 따라잡는다.
 */
@Service
@RequiredArgsConstructor
public class WarrantRevocationService {

    private final WarrantRepository warrants;
    private final WarrantSealer sealer;

    @Transactional
    public Warrant revoke(UUID id) {
        Warrant w = warrants.findById(id).orElseThrow(() -> new IllegalArgumentException("unknown warrant " + id));
        if (!w.isRevoked()) {
            w.revoke();
            sealer.seal(w);
        }
        return w;
    }
}
