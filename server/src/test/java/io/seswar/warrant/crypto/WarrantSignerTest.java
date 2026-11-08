package io.seswar.warrant.crypto;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

class WarrantSignerTest {

    @TempDir
    Path dir;

    byte[] payload = "warrant bytes".getBytes(StandardCharsets.UTF_8);

    @Test
    void 키_파일이_없으면_새로_만들고_다음에도_같은_키를_쓴다() {
        Path key = dir.resolve("signing.key");
        SigningKeyProvider first = new SigningKeyProvider(key.toString(), "central");
        SigningKeyProvider second = new SigningKeyProvider(key.toString(), "central");

        assertThat(Files.exists(key)).isTrue();
        assertThat(second.publicKeyPem()).isEqualTo(first.publicKeyPem());
    }

    @Test
    void 서명한_바이트는_같은_키로_검증된다() {
        WarrantSigner signer = new WarrantSigner(new SigningKeyProvider(dir.resolve("k").toString(), "central"));

        byte[] sig = signer.sign(payload);

        assertThat(sig).hasSize(64);
        assertThat(signer.verify(payload, sig)).isTrue();
        assertThat(signer.keyId()).isEqualTo("central");
    }

    @Test
    void 한_바이트라도_바뀌면_검증에_실패한다() {
        WarrantSigner signer = new WarrantSigner(new SigningKeyProvider(dir.resolve("k").toString(), "central"));
        byte[] sig = signer.sign(payload);

        byte[] tampered = payload.clone();
        tampered[0] ^= 1;

        assertThat(signer.verify(tampered, sig)).isFalse();
    }

    // 노드(warrantd)는 이 PEM 을 /etc/warrantd/keys/<key_id>.pem 으로 받아 그대로 읽는다.
    @Test
    void 공개키는_노드가_읽는_PEM_형식이고_서명을_검증한다() throws Exception {
        SigningKeyProvider keys = new SigningKeyProvider(dir.resolve("k").toString(), "central");
        WarrantSigner signer = new WarrantSigner(keys);
        String pem = keys.publicKeyPem();

        assertThat(pem).startsWith("-----BEGIN PUBLIC KEY-----\n").endsWith("-----END PUBLIC KEY-----\n");
        String b64 = pem.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
        PublicKey pub = KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(b64)));
        Signature v = Signature.getInstance("Ed25519");
        v.initVerify(pub);
        v.update(payload);
        assertThat(v.verify(signer.sign(payload))).isTrue();
    }
}
