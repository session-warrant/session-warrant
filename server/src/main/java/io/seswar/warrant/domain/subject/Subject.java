package io.seswar.warrant.domain.subject;

import java.util.UUID;

/**
 * 영장의 주체 — 사람. 영장은 uid 가 아니라 사람에 걸리므로 sudo 뒤로 숨지 못한다(§01).
 * 신원의 출처는 OIDC {@code sub} 다.
 */
// @Entity @Table(name = "subject")
public class Subject {

    private UUID id;

    /** OIDC {@code sub}. 조직 신원과 이 서버를 잇는 유일한 끈이다. */
    private String oidcSubject;

    /** 예: {@code paul@seswar.io}. 감사 리포트에 찍히는 이름표. */
    private String principal;

    private String displayName;

    /**
     * 커널로 내려가는 정수 id ({@code struct warrant.subject_id}, u32).
     *
     * <p>UUID 를 커널에 내리지 않는 이유는 맵 키 크기와 비교 비용 때문이다.
     * 이 정수 → 사람 매핑은 감사 저장소가 들고 있고, 리포트 시점에 조인된다(§10).
     */
    private int kernelSubjectId;

    /** 로그인 계정. 예: {@code ec2-user}. 여러 사람이 공유하므로 신원이 아니라 참고 정보다. */
    private String loginAccount;
}
