package io.seswar.warrant.signing;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.security.GeneralSecurityException;
import java.security.Signature;

/**
 * 영장 서명 — Ed25519 (JDK 내장).
 *
 * <p><b>protobuf 직렬화 바이트에 서명한다. JSON 에 서명하면 안 된다</b> — 키 순서와 공백의
 * 정규화 문제로 "검증에 실패하는데 내용은 같다"는 버그가 나온다. 서명한 바이트를 그대로 보관했다가
 * 그대로 전송한다 — 중간에 역직렬화 후 재직렬화하는 코드가 끼면 서명이 깨진다.
 */
@Component
@RequiredArgsConstructor
public class WarrantSigner {

    private final SigningKeyProvider keys;

    /** @return 64바이트 Ed25519 서명 */
    public byte[] sign(byte[] serializedWarrant) {
        try {
            Signature s = Signature.getInstance("Ed25519");
            s.initSign(keys.signingKey());
            s.update(serializedWarrant);
            return s.sign();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("sign warrant", e);
        }
    }

    /** 서버 자체 검증(회귀 테스트)용. 실제 검증 주체는 warrantd 다. */
    public boolean verify(byte[] serializedWarrant, byte[] signature) {
        try {
            Signature s = Signature.getInstance("Ed25519");
            s.initVerify(keys.verificationKey());
            s.update(serializedWarrant);
            return s.verify(signature);
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    /** proto {@code SignedWarrant.key_id}. 노드는 이 이름의 .pem 으로 검증한다. */
    public String keyId() {
        return keys.keyId();
    }
}
