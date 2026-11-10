package io.seswar.warrant.identity;

import io.seswar.warrant.identity.Subject;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

/**
 * {@code kernelSubjectId}(u32) 할당은 DB 시퀀스가 한다.
 * <b>재사용하면 안 된다</b> — 퇴사자의 id 를 신규 입사자에게 다시 주면
 * 과거 감사 로그의 귀속이 조용히 뒤바뀐다.
 */
public interface SubjectRepository extends JpaRepository<Subject, UUID> {

    Optional<Subject> findByOidcSubject(String oidcSubject);

    // Called by AuthController: the subject whose principal is the logged-in email.
    Optional<Subject> findByPrincipal(String principal);

    // 감사 조회 시점의 조인
    Optional<Subject> findByKernelSubjectId(int kernelSubjectId);
}
