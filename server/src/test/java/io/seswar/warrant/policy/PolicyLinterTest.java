package io.seswar.warrant.policy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;

import static io.seswar.warrant.policy.WriteRule.Effect.ALLOW;
import static io.seswar.warrant.policy.WriteRule.Effect.DENY;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PolicyLinterTest {

    PolicyLinter linter = new PolicyLinter();

    static Policy writes(WriteRule... rules) {
        return Policy.of("p", false, List.of(), List.of(rules), List.of());
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "/etc/warrantd",            // 같은 경로 ALLOW 는 기본 DENY 뒤에 들어가 이긴다
            "/etc/warrantd/keys",       // 아래 경로 ALLOW 는 최장 일치로 이긴다
            "/var/lib/warrantd/",
            "/run/warrantd",
            "/var/run/warrantd",        // /run 의 심볼릭 링크 — 노드에서 같은 inode 로 컴파일된다
            "/etc//warrantd",
            "/etc/./warrantd/x",
            "/etc/foo/../warrantd",
    })
    void warrantd_자기_상태를_여는_쓰기_허용은_거부한다(String path) {
        assertThatThrownBy(() -> linter.assertDoesNotWeakenSelfProtection(writes(new WriteRule(path, true, ALLOW))))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("self-protection");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "/etc",                     // 위쪽 ALLOW 는 더 긴 기본 DENY 에 진다 — 열리지 않는다
            "/",
            "/etc/warrantd-backup",     // 이름이 겹칠 뿐 다른 디렉터리
            "/var/lib/warrant",
            "/tmp",
    })
    void 자기보호와_무관한_쓰기_허용은_통과한다(String path) {
        assertThatCode(() -> linter.assertDoesNotWeakenSelfProtection(writes(new WriteRule(path, true, ALLOW))))
                .doesNotThrowAnyException();
    }

    @Test
    void 자기_디렉터리에_대한_DENY_는_약화가_아니다() {
        assertThatCode(() -> linter.assertDoesNotWeakenSelfProtection(
                writes(new WriteRule("/etc/warrantd", true, DENY))))
                .doesNotThrowAnyException();
    }

    @Test
    void 규칙이_없는_정책은_통과한다() {
        assertThatCode(() -> linter.assertDoesNotWeakenSelfProtection(writes()))
                .doesNotThrowAnyException();
    }
}
