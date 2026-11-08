package io.seswar.warrant.api;

import io.seswar.warrant.crypto.SigningKeyProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 노드에 심을 서명 공개키. 응답 본문을 그대로 {@code /etc/warrantd/keys/<X-Key-Id>.pem} 에 저장한다.
 * 런타임에 노드가 이걸 받아 가게 만들지 말 것 — 배포 시점에 심는다(SigningKeyProvider).
 */
@RestController
@RequiredArgsConstructor
public class SigningKeyController {

    private final SigningKeyProvider keys;

    @GetMapping(value = "/api/signing-key", produces = MediaType.TEXT_PLAIN_VALUE)
    public ResponseEntity<String> publicKey() {
        return ResponseEntity.ok().header("X-Key-Id", keys.keyId()).body(keys.publicKeyPem());
    }
}
