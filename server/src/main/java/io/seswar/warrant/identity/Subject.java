package io.seswar.warrant.identity;

import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.Generated;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * 영장의 주체 — 사람. 영장은 uid 가 아니라 사람에 걸리므로 sudo 뒤로 숨지 못한다(§01).
 * 신원의 출처는 OIDC {@code sub} 다.
 */
@Entity
@Table(name = "subject")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Subject {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /** OIDC {@code sub}. 조직 신원과 이 서버를 잇는 유일한 끈이다. */
    @Column(nullable = false, unique = true)
    private String oidcSubject;

    /** 예: {@code paul@seswar.io}. 감사 리포트에 찍히는 이름표. */
    @Column(nullable = false)
    private String principal;

    private String displayName;

    /**
     * 커널로 내려가는 정수 id ({@code struct warrant.subject_id}, u32). DB 시퀀스가 매기고 재사용하지 않는다.
     * 이 정수 → 사람 매핑은 감사 저장소가 들고 있고, 리포트 시점에 조인된다(§10).
     */
    @Generated
    @Column(insertable = false, updatable = false)
    private int kernelSubjectId;

    /** 로그인 계정. 예: {@code ec2-user}. 여러 사람이 공유하므로 신원이 아니라 참고 정보다. */
    private String loginAccount;

    /**
     * 등록된 SSH 공개키 지문({@code SHA256:...}). 발급 시 영장으로 복사돼 함께 서명된다.
     * 공유 계정에서 사람을 가르는 유일한 키다 — 비어 있으면 영장이 어떤 세션에도 붙지 않는다.
     */
    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "subject_ssh_key", joinColumns = @JoinColumn(name = "subject_id"))
    @Column(name = "fingerprint", nullable = false)
    private List<String> sshKeyFingerprints = new ArrayList<>();

    public static Subject of(String oidcSubject, String principal, String loginAccount, List<String> fingerprints) {
        Subject s = new Subject();
        s.oidcSubject = oidcSubject;
        s.principal = principal;
        s.loginAccount = loginAccount;
        s.sshKeyFingerprints = new ArrayList<>(fingerprints);
        return s;
    }
}
