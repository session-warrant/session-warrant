package io.seswar.warrant.domain.warrant;

/**
 * 유효기간의 <b>모든</b> 변경은 영장에 계보로 남는다(§03).
 * 감사에서 "30분짜리 작업이 왜 90분이었나"가 이 이력 그대로 설명되어야 한다.
 */
public enum LineageType {

    REQUESTED,

    /** 발급 요청이 반려됨. */
    REJECTED,

    /** 발급. 승인자 · 사유 · 원 기간이 함께 남는다. */
    ISSUED,

    /** 연장 요청. 사람이 콘솔에서 올렸거나 warrantd 가 T-5분에 올렸다. 열려 있는 동안 승인 큐에 뜬다. */
    EXTENSION_REQUESTED,

    /** 승인자가 콘솔에서 승인해 연장. */
    EXTENDED,

    /**
     * 정책 자동 승인으로 연장. <b>"자동 승인됨"이라는 사실 자체도 기록된다</b> —
     * 근거(어떤 정책의 몇 회차인지)를 반드시 함께 남긴다.
     */
    AUTO_EXTENDED,

    /** 연장 요청이 반려됨. */
    EXTENSION_DENIED,

    REVOKED,

    EXPIRED,

    /** 유예 진입. 그 자체로 경보 대상이다 — "김개발 로그아웃, 잡 2개 유예 실행 중". */
    GRACE_ENTERED,

    /** 유예 잡이 전부 끝나 영장이 완전히 닫힘. */
    GRACE_CLOSED,

    /** 누적 상한 도달로 연장이 아니라 재발급된 경우. 새 사유 · 새 승인이 붙는다. */
    REISSUED
}
