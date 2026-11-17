package io.seswar.warrant.policy;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

class PolicyRulesTest {

    @ParameterizedTest
    @ValueSource(strings = {"/usr/bin/systemctl", "/usr/bin/systemd-run", "/usr/bin/at", "/usr/bin/crontab",
            "/usr/bin/docker", "/snap/bin/docker"})
    void 위임_경로_바이너리는_위임_벡터다(String path) {
        assertThat(new ExecRule(path).isDelegationVector()).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"/usr/bin/git", "/usr/bin/ls", "/usr/bin/batch-tool", "/usr/bin/dockerd-rootless",
            "/opt/systemctl/bin/ls"})
    void 이름이_다르면_위임_벡터가_아니다(String path) {
        assertThat(new ExecRule(path).isDelegationVector()).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {"0.0.0.0/0", "::/0"})
    void 접두사_0_은_전면_허용이다(String cidr) {
        assertThat(new NetRule(cidr, 443, NetRule.Proto.TCP).isWideOpen()).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"10.0.0.0/8", "0.0.0.0/1", "192.168.1.10", "2001:db8::/32", "10.0.0.0/0x"})
    void 그_밖의_대역은_전면_허용이_아니다(String cidr) {
        assertThat(new NetRule(cidr, 0, NetRule.Proto.ANY).isWideOpen()).isFalse();
    }
}
