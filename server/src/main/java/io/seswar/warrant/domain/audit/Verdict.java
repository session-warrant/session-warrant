package io.seswar.warrant.domain.audit;

/** 커널 훅의 판정 결과. 정수값은 proto {@code Verdict} 와 같다. */
public enum Verdict {

    ALLOW(0),

    /** 실제로 -EPERM 을 돌려준 경우. */
    DENY(1),

    /**
     * DRYRUN 이라 막지 않고 기록만 한 경우.
     * 강제로 켰다면 막혔을 건이므로, 최소 권한 초안 검증의 핵심 데이터다(§07 STEP 3).
     */
    WOULD_DENY(2);

    private final int wireValue;

    Verdict(int wireValue) {
        this.wireValue = wireValue;
    }

    public int wireValue() {
        return wireValue;
    }

    public static Verdict fromWire(int value) {
        for (Verdict v : values()) {
            if (v.wireValue == value) {
                return v;
            }
        }
        throw new IllegalArgumentException("unknown Verdict wire value: " + value);
    }
}
