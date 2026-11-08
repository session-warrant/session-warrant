package io.seswar.warrant.identity;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

/** 로그인한 사람의 주체. 신청자 · 승인자는 요청 본문이 아니라 여기서 온다 — 본문은 아무 이름이나 적을 수 있다. */
@Component
@RequiredArgsConstructor
public class CurrentSubject {

    private final SubjectRepository subjects;

    // Called by WarrantController and ApprovalController. A login with no subject cannot request or decide.
    public Subject require(Authentication auth) {
        return subjects.findByPrincipal(auth.getName())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.FORBIDDEN, "no subject for " + auth.getName()));
    }
}
