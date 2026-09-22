package io.seswar.warrant.domain.policy;

/**
 * 아웃바운드 허용 대역. 커널에서는 {@code (policy_id, CIDR)} 키의 LPM 트라이 엔트리가 된다.
 *
 * <p>읽기 통제를 포기한 대가를 여기서 메운다 — <b>읽을 수는 있어도 밖으로 내보낼 수 없다</b>(§15).
 * 그래서 이 목록을 넓게 여는 것은 읽기 통제 포기와 곱해져서 위험해진다.
 *
 * <p>{@code port} 가 null 이면 모든 포트 (wire 0).
 */
// @Embeddable
public record NetRule(String cidr, Integer port, Proto proto) {

    /**
     * wire 값은 proto {@code Proto} 와 같다. UDP 규칙은 정책의 inspectUdp 가 true 일 때만 강제된다 —
     * "TCP 443 허용, UDP 443 금지"를 쓰려면 이 축이 필요하다(§18 UDP 구멍).
     */
    public enum Proto {
        ANY(0),
        TCP(1),
        UDP(2);

        private final int wireValue;

        Proto(int wireValue) {
            this.wireValue = wireValue;
        }

        public int wireValue() {
            return wireValue;
        }
    }

    public boolean isWideOpen() {
        // 0.0.0.0/0 · ::/0 처럼 사실상 전면 허용인가.
        // "범위가 전부 허용이면 아무것도 통제하지 않는다"(§06) — lint 경고 대상.
        throw new UnsupportedOperationException("미구현");
    }
}
