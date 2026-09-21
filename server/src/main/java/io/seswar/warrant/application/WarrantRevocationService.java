package io.seswar.warrant.application;

import java.util.UUID;

/**
 * 회수. 연장과 같은 경로(새 revision push)이고, 커널에서는 {@code warrants[id].revoked = 1}
 * 한 바이트로 즉시 발효된다(§03, §05).
 */
// @Service @Transactional
public class WarrantRevocationService {

    public void revoke(UUID warrantId, UUID actorId, String reason) {
        // 1. warrant.revoke(actorId, reason)  — DB 먼저. push 실패해도 취소 사실은 남아야 한다
        // 2. 대상 노드 전부에 push. 스트림이 끊긴 노드는 재연결 시 전체 동기화로 따라잡는다
        // 3. 노드 하나라도 push 실패하면 그 사실을 경보한다 —
        //    "취소했다고 믿는데 아직 살아 있는" 상태가 가장 위험하다
        throw new UnsupportedOperationException("미구현");
    }

    /**
     * 주체 단위 일괄 회수. 계정 탈취 대응 · 퇴사 처리용.
     */
    public int revokeAllForSubject(UUID subjectId, UUID actorId, String reason) {
        throw new UnsupportedOperationException("미구현");
    }
}
