package io.seswar.warrant.policy;

import org.springframework.stereotype.Component;

import java.util.List;

/**
 * 정책 설계 원칙(§04)을 코드로 강제하는 곳.
 *
 * <p><b>실행 허용 목록과 쓰기 허용 목록은 반드시 함께 검토해야 한다.</b>
 * 운영상 {@code systemctl restart} 를 허용해야 하는 영장이라면,
 * {@code /etc/systemd/system} 쓰기를 같이 열어주는 순간 임의 코드 실행 경로가 생긴다.
 * 둘 중 하나만 보고는 안전을 보장할 수 없다.
 */
@Component
public class PolicyLinter {

    public List<PolicyLintFinding> lint(Policy policy) {
        // 최소한 아래는 잡아야 한다.
        //
        // 1) EXEC_WRITE_COMBO  — 위임 벡터 바이너리 실행 허용 + 그 설정 디렉터리 쓰기 허용의 조합
        //      systemctl        + /etc/systemd/system
        //      docker           + /etc/docker, docker.sock
        //      crontab · at     + /var/spool/*
        //      아무 인터프리터  + 그 인터프리터가 읽는 경로 쓰기 허용
        // 2) DENY_ON_FILE_INODE — DENY 규칙이 파일을 가리킨다 (mv 후 재생성으로 뚫림)
        // 3) NET_WIDE_OPEN      — 아웃바운드가 사실상 전면 허용
        // 4) SELF_PROTECTION_TOUCH — §16 자기보호 6종이 덮는 대상을 정책이 열려 한다.
        //                            이건 WARN 이 아니라 ERROR 다. 아래 주석 참조.
        // 5) SCOPE_TOO_WIDE      — 실행 허용에 셸(bash/sh/python 등)이 들어 있어
        //                            화이트리스트가 사실상 무의미해진 경우
        throw new UnsupportedOperationException("미구현");
    }

    /**
     * 자기 보호 6종(§16)은 <b>정책이 아니라 제품이 강제로 삽입하는 기본 규칙</b>이다.
     * 영장 작성자가 실수로든 고의로든 열 수 없어야 하고, 하나라도 열리면 나머지가 무의미해진다.
     *
     * <p>따라서 이 메서드는 "경고"가 아니라 <b>발급 거부</b>로 이어져야 한다.
     * 유일한 예외는 break-glass 영장이며, 그건 별도 경로로 최고 등급 경보와 함께 발급된다.
     */
    public void assertDoesNotWeakenSelfProtection(Policy policy) {
        // 여섯 중 다섯(bpf · task_kill · sb_umount · ptrace_access_check · kernel_module_request)은
        // 규칙 조회가 없는 LSM 훅이라 정책으로는 열 수 없다(bpf/warrant.bpf.c 「자기보호 5종」).
        // 정책이 열 수 있는 건 여섯 번째뿐이다 — warrantd 자기 파일 쓰기 금지는 agent/internal/policy 가
        // 깔아 두는 DENY 규칙이고, 정책의 같은 경로 ALLOW 는 뒤에 들어가 이기고(같은 키),
        // 그 아래 경로 ALLOW 는 최장 일치로 이긴다. 그래서 그 두 모양만 막으면 된다.
        for (WriteRule r : policy.getWriteRules()) {
            if (r.effect() != WriteRule.Effect.ALLOW) {
                continue;
            }
            String path = normalize(r.path());
            for (String dir : SELF_PROTECTED_DIRS) {
                if (path.equals(dir) || path.startsWith(dir + "/")) {
                    throw new IllegalArgumentException(
                            "write rule " + r.path() + " opens warrantd's own state (" + dir + ", §16 self-protection)");
                }
            }
        }
    }

    /**
     * agent/internal/policy.DefaultDenyWrite 와 같은 목록이다 — <b>한쪽을 고치면 다른 쪽도 고친다.</b>
     * {@code /var/run} 은 Ubuntu 에서 {@code /run} 의 심볼릭 링크다. warrantd 는 경로를 stat 해서
     * inode 로 컴파일하므로 {@code /var/run/warrantd} ALLOW 도 같은 디렉터리를 연다.
     */
    static final List<String> SELF_PROTECTED_DIRS = List.of(
            "/var/lib/warrantd",
            "/run/warrantd",
            "/var/run/warrantd",
            "/etc/warrantd");

    // "/etc//warrantd/", "/etc/./warrantd" 같은 표기로 비켜 가지 못하게 한다. 경로는 노드의 것이라
    // 서버 파일 시스템을 보지 않고 문자열로만 정리한다.
    private static String normalize(String path) {
        String p = java.nio.file.Path.of(path).normalize().toString();
        return p.length() > 1 && p.endsWith("/") ? p.substring(0, p.length() - 1) : p;
    }
}
