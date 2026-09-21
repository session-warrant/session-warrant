package io.seswar.warrant.crypto;

/**
 * 영장 서명 — Ed25519 (JDK 내장).
 *
 * <p><b>protobuf 직렬화 바이트에 서명한다. JSON 에 서명하면 안 된다</b> — 키 순서와 공백의
 * 정규화 문제로 "검증에 실패하는데 내용은 같다"는 버그가 나온다. 서명한 바이트를 그대로 보관했다가
 * 그대로 전송한다 — 중간에 역직렬화 후 재직렬화하는 코드가 끼면 서명이 깨진다.
 */
// @Component
public class WarrantSigner {

    public byte[] sign(byte[] serializedWarrant) {
        // Signature.getInstance("Ed25519") → initSign(privateKey) → update → sign
        throw new UnsupportedOperationException("미구현");
    }

    /**
     * 검증. 서버에서는 자체 검증(회귀 테스트)용이고,
     * 실제 검증 주체는 warrantd 다 — 중앙 단절 시에도 캐시된 영장을 오프라인으로 확인해야 하기 때문이다.
     *
     * <p>PAM 모듈은 검증하지 않는다. <b>인증 경로에 암호 연산을 넣지 않는다</b>(기술 스택 §05).
     */
    public boolean verify(byte[] serializedWarrant, byte[] signature) {
        throw new UnsupportedOperationException("미구현");
    }
}
