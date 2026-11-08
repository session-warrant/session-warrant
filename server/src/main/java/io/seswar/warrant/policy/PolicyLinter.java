package io.seswar.warrant.policy;

import java.util.List;

/**
 * 정책 설계 원칙(§04)을 코드로 강제하는 곳.
 *
 * <p><b>실행 허용 목록과 쓰기 허용 목록은 반드시 함께 검토해야 한다.</b>
 * 운영상 {@code systemctl restart} 를 허용해야 하는 영장이라면,
 * {@code /etc/systemd/system} 쓰기를 같이 열어주는 순간 임의 코드 실행 경로가 생긴다.
 * 둘 중 하나만 보고는 안전을 보장할 수 없다.
 */
// @Component
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
        // bpf() syscall · task_kill(warrantd·sshd) · sb_umount(/sys/fs/bpf)
        // · ptrace_access_check · kernel_module_request · warrantd 자기 파일 쓰기
        throw new UnsupportedOperationException("미구현");
    }
}
