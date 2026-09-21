package io.seswar.warrant.crypto;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * 공개키는 노드가 오프라인 검증에 쓰므로 <b>배포 시점에 노드에 심는다</b> —
 * 런타임에 중앙에서 받아오게 만들면 중앙 단절 시 검증이 불가능해지고,
 * 그 경로 자체가 키 교체 공격면이 된다.
 */
// @Component
public class SigningKeyProvider {

    public PrivateKey signingKey() {
        // 데모에서는 파일/환경변수, 운영에서는 KMS·HSM.
        // 어느 쪽이든 키가 코드나 리포지토리에 들어가지 않게 한다.
        throw new UnsupportedOperationException("미구현");
    }

    public PublicKey verificationKey() {
        throw new UnsupportedOperationException("미구현");
    }

    /**
     * 키 교체. 노드가 구키로 서명된 캐시 영장을 들고 있을 수 있으므로
     * <b>검증 키는 겹치는 구간 동안 둘 다 유효해야 한다</b>.
     */
    public void rotate() {
        throw new UnsupportedOperationException("미구현");
    }
}
