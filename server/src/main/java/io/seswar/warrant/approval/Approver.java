package io.seswar.warrant.approval;

import java.util.Set;
import java.util.UUID;

/**
 * 결정하는 사람 — 주체 id 와 로그인이 들고 온 그룹. 그룹은 요청 본문이 아니라 로그인(Keycloak {@code groups} claim ·
 * dev 계정 설정)에서 온다({@code CurrentSubject.groups}). 본문은 아무 그룹이나 적을 수 있다.
 */
public record Approver(UUID id, Set<String> groups) {

    public Approver {
        groups = Set.copyOf(groups);
    }

    public boolean isIn(String group) {
        return groups.contains(group);
    }
}
