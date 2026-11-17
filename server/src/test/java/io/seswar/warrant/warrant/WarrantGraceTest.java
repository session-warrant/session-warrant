package io.seswar.warrant.warrant;

import io.seswar.warrant.identity.Subject;
import io.seswar.warrant.policy.Policy;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class WarrantGraceTest {

    static final Instant T0 = Instant.parse("2026-11-17T09:00:00Z");
    static final Duration LIFE = Duration.ofMinutes(30);
    static final Instant EXPIRES = T0.plus(LIFE);

    static Warrant warrant(OnExpiry onExpiry, Duration graceWindow) {
        Warrant w = Warrant.issue(Subject.of("oidc|a", "a@example.com", "ec2-user", List.of("SHA256:a")),
                Policy.of("p", false, List.of(), List.of(), List.of()), "ec2-user", "INC-1",
                List.of("node-1"), T0, LIFE, WarrantMode.DRYRUN, onExpiry);
        // graceWindow is not mapped or settable yet (the column keeps its DB default 0).
        ReflectionTestUtils.setField(w, "graceWindow", graceWindow);
        return w;
    }

    @Test
    void 유예_종료는_만료_더하기_유예_기간이다() {
        assertThat(warrant(OnExpiry.SESSION_ONLY_GRACE, Duration.ofMinutes(10)).graceUntil())
                .isEqualTo(EXPIRES.plus(Duration.ofMinutes(10)));
        assertThat(warrant(OnExpiry.DEMOTE, Duration.ZERO).graceUntil()).isEqualTo(EXPIRES);
    }

    @Test
    void 유예_구간은_만료_순간부터_유예_종료_직전까지다() {
        Warrant w = warrant(OnExpiry.SESSION_ONLY_GRACE, Duration.ofMinutes(10));

        assertThat(w.isInGraceAt(EXPIRES.minusNanos(1))).isFalse();      // 아직 유효
        assertThat(w.isInGraceAt(EXPIRES)).isTrue();                     // isExpiredAt 과 같은 경계
        assertThat(w.isInGraceAt(EXPIRES.plus(Duration.ofMinutes(5)))).isTrue();
        assertThat(w.isInGraceAt(w.graceUntil())).isFalse();             // 유예도 끝났다
    }

    @Test
    void 유예_모드가_아니면_유예_구간이_없다() {
        Warrant w = warrant(OnExpiry.KILL, Duration.ofMinutes(10));

        assertThat(w.isInGraceAt(EXPIRES.plus(Duration.ofMinutes(5)))).isFalse();
    }

    @Test
    void 유예_기간이_0_이면_유예_모드여도_구간이_비어_있다() {
        Warrant w = warrant(OnExpiry.SESSION_ONLY_GRACE, Duration.ZERO);

        assertThat(w.isInGraceAt(EXPIRES)).isFalse();
    }

    @Test
    void 유예_시한이_필수인_모드는_유예_하나뿐이다() {
        assertThat(OnExpiry.SESSION_ONLY_GRACE.requiresGraceWindow()).isTrue();
        assertThat(OnExpiry.DEMOTE.requiresGraceWindow()).isFalse();
        assertThat(OnExpiry.KILL.requiresGraceWindow()).isFalse();
    }
}
