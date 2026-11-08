package io.seswar.warrant.identity;

import io.seswar.warrant.identity.Subject;
import io.seswar.warrant.identity.SubjectRepository;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

/** 주체(사람) 등록 · 목록. 원래는 OIDC 로그인에서 오지만, 그 전까지 손으로 넣는다. */
@RestController
@RequestMapping("/api/subjects")
@RequiredArgsConstructor
public class SubjectController {

    private final SubjectRepository subjects;

    public record CreateSubject(@NotBlank String oidcSubject, @NotBlank String principal,
                                String loginAccount, List<String> sshKeyFingerprints) {
    }

    public record SubjectView(UUID id, int kernelSubjectId, String oidcSubject, String principal,
                              String loginAccount, List<String> sshKeyFingerprints) {
        static SubjectView of(Subject s) {
            return new SubjectView(s.getId(), s.getKernelSubjectId(), s.getOidcSubject(), s.getPrincipal(),
                    s.getLoginAccount(), List.copyOf(s.getSshKeyFingerprints()));
        }
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public SubjectView create(@Valid @RequestBody CreateSubject body) {
        List<String> keys = body.sshKeyFingerprints() == null ? List.of() : body.sshKeyFingerprints();
        return SubjectView.of(subjects.saveAndFlush(
                Subject.of(body.oidcSubject(), body.principal(), body.loginAccount(), keys)));
    }

    @GetMapping
    public List<SubjectView> list() {
        return subjects.findAll().stream().map(SubjectView::of).toList();
    }
}
