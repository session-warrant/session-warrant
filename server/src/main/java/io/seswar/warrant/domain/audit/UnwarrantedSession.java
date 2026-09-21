package io.seswar.warrant.domain.audit;

import java.time.Instant;
import java.util.UUID;

/** 영장 없이 성립한 SSH 세션(§07 STEP 2). */
// @Entity @Table(name = "unwarranted_session")
public class UnwarrantedSession {

    private UUID id;

    private UUID nodeId;

    private Instant observedAt;

    private String loginAccount;

    private String sourceAddress;

    private long cgroupId;

    /** PAM_TIMEOUT · NO_WARRANT · CENTRAL_UNREACHABLE · CACHE_EXPIRED 등. */
    private String reason;

    /**
     * 이 세션이 실제로 무엇을 했는지 — 연결된 감사 이벤트 수.
     * "무영장 세션이 몇 건 있었다"보다 "무영장 세션이 무엇을 했다"가 훨씬 강한 자료다.
     */
    private long observedEventCount;
}
