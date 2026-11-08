package io.seswar.warrant.application;

import io.seswar.warrant.crypto.WarrantSigner;
import io.seswar.warrant.domain.policy.Policy;
import io.seswar.warrant.domain.subject.Subject;
import io.seswar.warrant.domain.warrant.Warrant;
import io.seswar.warrant.grpc.WarrantProtoMapper;
import io.seswar.warrant.repository.PolicyRepository;
import io.seswar.warrant.repository.SubjectRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/** 영장의 현재 revision 을 protobuf 로 굳히고 서명한다. 발급 · 취소가 revision 을 바꿀 때마다 부른다. */
@Component
@RequiredArgsConstructor
public class WarrantSealer {

    private final SubjectRepository subjects;
    private final PolicyRepository policies;
    private final WarrantProtoMapper mapper;
    private final WarrantSigner signer;

    // Called by WarrantIssuanceService and WarrantRevocationService, after the warrant has its kernel id.
    public void seal(Warrant w) {
        Subject s = subjects.findById(w.getSubjectId()).orElseThrow();
        Policy p = policies.findById(w.getPolicyId()).orElseThrow();
        byte[] bytes = mapper.toSignedBytes(w, s, p);
        w.seal(bytes, signer.sign(bytes), signer.keyId());
    }
}
