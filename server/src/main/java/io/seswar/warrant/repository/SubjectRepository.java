package io.seswar.warrant.repository;

/**
 * {@code kernelSubjectId}(u32) 할당은 여기서 관리한다.
 * <b>재사용하면 안 된다</b> — 퇴사자의 id 를 신규 입사자에게 다시 주면
 * 과거 감사 로그의 귀속이 조용히 뒤바뀐다.
 */
// @Repository
public interface SubjectRepository /* extends JpaRepository<Subject, UUID> */ {

    // findByOidcSubject(String)
    // findByKernelSubjectId(int)   — 감사 조회 시점의 조인
}
