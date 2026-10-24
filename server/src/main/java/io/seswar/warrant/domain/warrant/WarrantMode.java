package io.seswar.warrant.domain.warrant;

/**
 * 영장의 집행 강도. {@code struct warrant.mode} 와 <b>정수값이 반드시 일치</b>해야 한다(§12).
 *
 * <p>mode 가 노드 전체가 아니라 <b>영장마다</b> 붙어 있는 것이 핵심이다.
 * 새 정책을 쓰는 팀만 DRYRUN 으로 두고 나머지는 ENFORCE 로 두는 운용이 가능해진다.
 */
public enum WarrantMode {

    /** 판정하되 아무것도 막지 않고 기록만 한다. 재부팅 없이 도는 도입 1단계(§07 STEP 1). */
    OBSERVE(0),

    /** 정책을 얹되 차단은 로그만. 최소 권한 초안이 실무를 방해하는지 확인하는 단계(§07 STEP 3). */
    DRYRUN(1),

    /** 실제로 -EPERM 을 돌려준다. BPF LSM(lsm=...,bpf) 이 켜져 있어야 한다. */
    ENFORCE(2);

    private final int wireValue;

    WarrantMode(int wireValue) {
        this.wireValue = wireValue;
    }

    public int wireValue() {
        return wireValue;
    }

    public static WarrantMode fromWire(int value) {
        // 알 수 없는 값이 오면 예외. 커널 구조체와 어긋난 상태로 조용히 넘어가면 안 된다.
        for (WarrantMode m : values()) {
            if (m.wireValue == value) {
                return m;
            }
        }
        throw new IllegalArgumentException("unknown WarrantMode wire value: " + value);
    }
}
