package io.seswar.warrant.warrant;

/**
 * 만료 순간의 동작. {@code struct warrant.on_expiry} 한 바이트가 결정한다(§03, §12).
 *
 * <p>어느 모드를 골라도 <b>진행 중인 작업은 깨진다</b>. 그래서 모드 선택만으로는 부족하고
 * 운영 수칙 세 겹(T-5분 경고 · 세션을 끊지 않는 연장 · 긴 작업은 파이프라인으로)이 함께 간다.
 */
public enum OnExpiry {

    /**
     * 기본 · 강등. 세션은 살고 권한만 죽는다.
     * 훅이 매 판정마다 시각을 비교하므로 warrantd 개입 없이 발효된다.
     * 저장 안 한 vi, 돌고 있는 배포가 티켓 만료로 죽는 사고를 피한다.
     */
    DEMOTE(0),

    /**
     * 옵션 · 종료. warrantd 가 세션 scope 의 프로세스를 일괄 종료한다.
     * warrantd 가 죽어 있어도 안전하다 — 만료된 프로세스가 다음 syscall 을 하는 순간
     * 훅에서 bpf_send_signal(SIGKILL) 로 처리된다.
     */
    KILL(1),

    /**
     * 옵션 · 유예. 셸과 sshd 세션 프로세스만 종료하고 nohup 잡은 살린다.
     *
     * <p><b>가장 위험한 모드다.</b> 순진하게 만들면 이 모드 자체가 우회 경로가 된다
     * ({@code nohup evil.sh &} 후 로그아웃 = 무기한 권한). 안전장치 넷이 함께 가야 한다:
     * <ol>
     *   <li>유예에도 시한이 있다 — {@code grace_ns}. 무기한 유예는 존재하지 않는다</li>
     *   <li>유예 중 신규 네트워크 연결 금지 — 배포는 계속되지만 리버스 셸은 전화를 못 건다</li>
     *   <li>유예 진입 자체가 기록 · 경보 대상</li>
     *   <li>유예 잡이 전부 끝나면 그 시점에 영장이 완전히 닫힌다</li>
     * </ol>
     */
    SESSION_ONLY_GRACE(2);

    private final int wireValue;

    OnExpiry(int wireValue) {
        this.wireValue = wireValue;
    }

    public int wireValue() {
        return wireValue;
    }

    public static OnExpiry fromWire(int v) {
        for (OnExpiry o : values()) {
            if (o.wireValue == v) {
                return o;
            }
        }
        throw new IllegalArgumentException("unknown OnExpiry wire value: " + v);
    }

    // Used by Warrant.onExpiry.
    @jakarta.persistence.Converter
    public static class Converter implements jakarta.persistence.AttributeConverter<OnExpiry, Short> {
        public Short convertToDatabaseColumn(OnExpiry o) { return o == null ? null : (short) o.wireValue(); }
        public OnExpiry convertToEntityAttribute(Short s) { return s == null ? null : OnExpiry.fromWire(s); }
    }

    /** 유예 시한(grace) 설정이 필수인 모드인가. */
    public boolean requiresGraceWindow() {
        // return this == SESSION_ONLY_GRACE;
        throw new UnsupportedOperationException("미구현");
    }
}
