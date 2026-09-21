package io.seswar.warrant.domain.warrant;

/**
 * 영장의 일생(§11). 이 값은 <b>커널로 내려가지 않는다</b> — 커널은 expires/revoked 만 본다.
 * 여기 상태는 계보(lineage)로부터 계산되는 서버 측 뷰다.
 */
public enum WarrantState {

    /** 요청됨. 아직 승인 전이라 노드로 내려가지 않았다. */
    REQUESTED,

    /** 승인됨 · 서명됨. push 대기 또는 push 완료. */
    ISSUED,

    /** 세션이 붙어 집행 중 (T1 바인딩 완료). */
    BOUND,

    /** 만료했으나 유예 잡이 남아 있다 (on_expiry = SESSION_ONLY_GRACE). */
    GRACE,

    EXPIRED,

    /** 취소 — revoked 한 바이트로 전 노드에서 즉시 발효된 상태. */
    REVOKED,

    /** 거부됨 (승인자가 반려). */
    REJECTED
}
