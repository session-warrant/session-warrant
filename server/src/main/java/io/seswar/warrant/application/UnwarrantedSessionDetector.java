package io.seswar.warrant.application;

import java.time.Instant;
import java.util.UUID;

/** 영장 없는 접속 탐지 — 게이트웨이를 우회한 접속을 호스트에서 잡아낸다(§07 STEP 2). */
// @Service
public class UnwarrantedSessionDetector {

    /**
     * warrantd 가 보고한 무영장 세션 등록. 무영장이라고 <b>차단하지 않는다</b> —
     * fail-close 를 택하면 장애 때 아무도 못 들어간다(§17 fail-open).
     */
    public void record(UUID nodeId, String loginAccount, String sourceAddress,
                       long cgroupId, String reason, Instant observedAt) {
        throw new UnsupportedOperationException("미구현");
    }

    /** 무영장 세션 리포트. 대시보드는 Grafana 로 붙이므로 여기서는 집계 쿼리만 제공한다. */
    public Object summarize(Instant from, Instant to) {
        // 노드별 · 계정별 · 출처별 건수와, 그 세션들이 실제로 무엇을 했는지(연결 이벤트 수)를 함께 낸다.
        throw new UnsupportedOperationException("미구현");
    }
}
