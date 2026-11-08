package io.seswar.warrant.domain.policy;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;

/**
 * 실행 허용 한 줄. 정책에는 {@code /usr/bin/git} 이라고 쓰지만 맵에는 inode 가 들어간다.
 *
 * <p>부수 효과로 <b>바이너리 복사 우회가 자동으로 막힌다</b> —
 * {@code /bin/bash} 를 {@code /tmp/git} 으로 복사해도 새 inode 라 허용 목록에 없다.
 * 대가는 패키지 업데이트로 inode 가 바뀌면 재컴파일이 필요하다는 것이고,
 * warrantd 가 fanotify 로 감시해 자동 갱신한다.
 */
@Embeddable
public record ExecRule(@Column(nullable = false) String path) {

    /**
     * 위임 경로로 악명 높은 바이너리인가.
     * {@code systemd-run · systemctl · at · crontab · docker} — 이들이 허용되면
     * §04 의 3중 방어 중 첫 겹이 열린다. 정책 lint 가 반드시 경고해야 한다.
     */
    public boolean isDelegationVector() {
        throw new UnsupportedOperationException("미구현");
    }
}
