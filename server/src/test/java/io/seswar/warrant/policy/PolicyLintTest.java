package io.seswar.warrant.policy;

import io.seswar.warrant.policy.PolicyLintFinding.Severity;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;

import static io.seswar.warrant.policy.WriteRule.Effect.ALLOW;
import static io.seswar.warrant.policy.WriteRule.Effect.DENY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PolicyLintTest {

    PolicyLinter linter = new PolicyLinter();

    static Policy policy(List<String> exec, List<WriteRule> writes, List<NetRule> nets) {
        return Policy.of("p", false, exec.stream().map(ExecRule::new).toList(), writes, nets);
    }

    static Policy execWrite(String exec, WriteRule... writes) {
        return policy(List.of(exec), List.of(writes), List.of());
    }

    List<String> codes(Policy p, Severity s) {
        return linter.lint(p).stream().filter(f -> f.severity() == s).map(PolicyLintFinding::code).toList();
    }

    // ── EXEC_WRITE_COMBO ─────────────────────────────────────────────────────────

    @ParameterizedTest
    @CsvSource({
            "/usr/bin/systemctl,   /etc/systemd/system, true",   // 설정 디렉터리를 직접 연다
            "/usr/bin/systemctl,   /etc,                true",   // 조상 recursive ALLOW 도 연다
            "/usr/bin/systemd-run, /run/systemd/system, false",  // 그 아래 직계만이어도 유닛을 떨굴 수 있다
            "/usr/bin/docker,      /etc/docker,         false",
            "/usr/bin/docker,      /var/run/docker.sock, false",
            "/usr/bin/crontab,     /var/spool/cron,     true",
            "/usr/bin/crontab,     /etc,                false",  // 직계 자식 /etc/crontab 을 쓸 수 있다
            "/usr/bin/at,          /var/spool,          true",
            "/usr/bin/systemctl,   /,                   true",
            "/usr/bin/sudo,        /etc/sudoers.d,      false",  // agent comboRules 와 같은 짝
            "/usr/bin/mount,       /etc,                false",  // 직계 자식 /etc/fstab
    })
    void 위임_바이너리와_그_설정_쓰기를_같이_열면_ERROR다(String exec, String path, boolean recursive) {
        Policy p = execWrite(exec, new WriteRule(path, recursive, ALLOW));

        assertThat(codes(p, Severity.ERROR)).contains(PolicyLinter.EXEC_WRITE_COMBO);
        assertThatThrownBy(() -> linter.assertNoErrors(p))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining(PolicyLinter.EXEC_WRITE_COMBO);
    }

    @ParameterizedTest
    @CsvSource({
            "/usr/bin/systemctl, /tmp,                 true",    // 무관한 경로
            "/usr/bin/systemctl, /etc/nginx,           true",
            "/usr/bin/systemctl, /etc/systemd-backup,  true",    // 이름이 겹칠 뿐 다른 디렉터리
            "/usr/bin/docker,    /etc/systemd/system,  true",    // 짝이 다르다 (docker 는 systemd 설정을 안 읽는다)
            "/usr/bin/crontab,   /var,                 false",   // 직계만 — /var/spool/cron 까지 안 닿는다
            "/usr/bin/git,       /etc/systemd/system,  true",    // 위임 바이너리가 아니다
    })
    void 짝이_안_맞으면_조합_ERROR가_아니다(String exec, String path, boolean recursive) {
        assertThat(codes(execWrite(exec, new WriteRule(path, recursive, ALLOW)), Severity.ERROR))
                .doesNotContain(PolicyLinter.EXEC_WRITE_COMBO);
    }

    @Test
    void 쓰기만_열고_위임_바이너리가_없으면_통과한다() {
        Policy p = policy(List.of("/usr/bin/ls"), List.of(new WriteRule("/etc/systemd/system", true, ALLOW)), List.of());

        assertThat(linter.lint(p)).isEmpty();
    }

    @Test
    void 위에서_열어도_같은_깊이_이상의_DENY_가_닫으면_통과한다() {
        Policy p = execWrite("/usr/bin/systemctl",
                new WriteRule("/", true, ALLOW),
                new WriteRule("/etc/systemd", true, DENY),
                new WriteRule("/run/systemd", true, DENY),
                new WriteRule("/var/run/systemd", true, DENY),
                new WriteRule("/lib/systemd", true, DENY),
                new WriteRule("/usr/lib/systemd", true, DENY));

        assertThat(codes(p, Severity.ERROR)).doesNotContain(PolicyLinter.EXEC_WRITE_COMBO);
    }

    @Test
    void recursive_가_아닌_DENY_는_손자를_못_닫는다() {
        // /etc/systemd 직계는 DENY 가 이기지만 /etc/systemd/system/x 는 /etc 의 recursive ALLOW 만 걸린다.
        Policy p = execWrite("/usr/bin/systemctl",
                new WriteRule("/etc", true, ALLOW),
                new WriteRule("/etc/systemd", false, DENY));

        assertThat(codes(p, Severity.ERROR)).contains(PolicyLinter.EXEC_WRITE_COMBO);
    }

    @Test
    void DENY_로_닫은_안쪽을_다시_ALLOW_로_열면_ERROR다() {
        Policy p = execWrite("/usr/bin/systemctl",
                new WriteRule("/etc/systemd", true, DENY),
                new WriteRule("/etc/systemd/system", false, ALLOW));

        assertThat(codes(p, Severity.ERROR)).contains(PolicyLinter.EXEC_WRITE_COMBO);
    }

    @Test
    void 같은_경로에_ALLOW_와_DENY_가_같이_있으면_DENY_가_이긴다() {
        Policy p = execWrite("/usr/bin/docker",
                new WriteRule("/etc/docker", true, ALLOW),
                new WriteRule("/etc/docker", true, DENY));

        assertThat(codes(p, Severity.ERROR)).doesNotContain(PolicyLinter.EXEC_WRITE_COMBO);
    }

    // ── SELF_PROTECTION_TOUCH ────────────────────────────────────────────────────

    @Test
    void 자기보호를_여는_쓰기는_lint_에서도_ERROR다() {
        Policy p = policy(List.of(), List.of(new WriteRule("/etc/warrantd/keys", true, ALLOW)), List.of());

        assertThat(codes(p, Severity.ERROR)).containsExactly(PolicyLinter.SELF_PROTECTION_TOUCH);
        assertThatThrownBy(() -> linter.assertNoErrors(p)).hasMessageContaining("self-protection");
    }

    // ── WARN ─────────────────────────────────────────────────────────────────────

    @Test
    void 전면_허용_네트워크는_WARN_이고_막지_않는다() {
        Policy p = policy(List.of(), List.of(), List.of(new NetRule("0.0.0.0/0", 443, NetRule.Proto.TCP)));

        assertThat(codes(p, Severity.WARN)).containsExactly(PolicyLinter.NET_WIDE_OPEN);
        assertThat(linter.warnings(p)).hasSize(1);
        assertThatCode(() -> linter.assertNoErrors(p)).doesNotThrowAnyException();
    }

    @ParameterizedTest
    @ValueSource(strings = {"/bin/bash", "/usr/bin/sh", "/usr/bin/python3", "/usr/bin/python3.12", "/usr/bin/perl",
            "/usr/bin/node", "/usr/bin/env", "/bin/busybox"})
    void 셸과_인터프리터_실행_허용은_WARN_이다(String exec) {
        Policy p = policy(List.of(exec), List.of(), List.of());

        assertThat(codes(p, Severity.WARN)).containsExactly(PolicyLinter.SCOPE_TOO_WIDE);
        assertThatCode(() -> linter.assertNoErrors(p)).doesNotThrowAnyException();
    }

    @ParameterizedTest
    @ValueSource(strings = {"/usr/bin/git", "/usr/bin/bashful", "/usr/bin/pythonista", "/usr/bin/shred"})
    void 이름이_비슷할_뿐인_바이너리는_경고하지_않는다(String exec) {
        assertThat(linter.lint(policy(List.of(exec), List.of(), List.of()))).isEmpty();
    }

    @ParameterizedTest
    @CsvSource({
            "/etc/cron.d,         false",   // cron 은 실행 허용 없이도 돌린다
            "/etc,                false",   // 직계 자식 /etc/passwd · /etc/crontab
            "/etc/profile.d,      true",
            "/root,               true",
    })
    void 그_자체로_위험한_쓰기는_WARN_이다(String path, boolean recursive) {
        Policy p = policy(List.of(), List.of(new WriteRule(path, recursive, ALLOW)), List.of());

        assertThat(codes(p, Severity.WARN)).contains(PolicyLinter.RISKY_WRITE);
        assertThatCode(() -> linter.assertNoErrors(p)).doesNotThrowAnyException();
    }

    @Test
    void 실행_허용_바이너리를_쓸_수_있으면_WARN_이다() {
        Policy p = policy(List.of("/opt/tool/bin/run"), List.of(new WriteRule("/opt/tool", true, ALLOW)), List.of());

        assertThat(codes(p, Severity.WARN)).containsExactly(PolicyLinter.EXEC_IN_WRITABLE_DIR);
    }

    @Test
    void 평범한_정책은_아무것도_안_나온다() {
        Policy p = policy(List.of("/usr/bin/ls", "/usr/bin/git"),
                List.of(new WriteRule("/tmp", true, ALLOW), new WriteRule("/etc/passwd-dir", true, DENY)),
                List.of(new NetRule("10.0.0.0/8", 443, NetRule.Proto.TCP)));

        assertThat(linter.lint(p)).isEmpty();
    }
}
