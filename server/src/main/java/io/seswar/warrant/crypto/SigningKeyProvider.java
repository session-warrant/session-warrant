package io.seswar.warrant.crypto;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * 영장 서명 키 (Ed25519). 개인키는 {@code key-path}, 공개키는 그 옆 {@code key-path.pub} 에 PEM 으로 둔다.
 * 파일이 없으면 새로 만든다 — 로컬 개발용이다. 운영은 KMS · HSM.
 *
 * <p>공개키는 노드가 오프라인 검증에 쓰므로 <b>배포 시점에 노드에 심는다</b>
 * ({@code /etc/warrantd/keys/<keyId>.pem}). 키가 바뀌면 노드는 그 뒤 push 를 전부 거부한다.
 */
@Slf4j
@Component
public class SigningKeyProvider {

    private final String keyId;
    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    public SigningKeyProvider(@Value("${warrant.signing.key-path}") String keyPath,
                              @Value("${warrant.signing.key-id:central}") String keyId) {
        this.keyId = keyId;
        Path priv = Path.of(keyPath);
        Path pub = Path.of(keyPath + ".pub");
        try {
            if (!Files.exists(priv)) {
                generate(priv, pub);
            }
            KeyFactory kf = KeyFactory.getInstance("Ed25519");
            this.privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(readPem(priv)));
            this.publicKey = kf.generatePublic(new X509EncodedKeySpec(readPem(pub)));
        } catch (IOException e) {
            throw new UncheckedIOException("signing key " + keyPath, e);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("signing key " + keyPath, e);
        }
    }

    public String keyId() {
        return keyId;
    }

    public PrivateKey signingKey() {
        return privateKey;
    }

    public PublicKey verificationKey() {
        return publicKey;
    }

    /** 노드에 심을 공개키. PKIX(X.509 SubjectPublicKeyInfo) 를 PEM 으로 감싼 것 — warrantd 가 그대로 읽는다. */
    public String publicKeyPem() {
        return pem("PUBLIC KEY", publicKey.getEncoded());
    }

    // Called by the constructor when no key exists yet. The private key file is 0600.
    private static void generate(Path priv, Path pub) throws IOException, GeneralSecurityException {
        KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        if (priv.getParent() != null) {
            Files.createDirectories(priv.getParent());
        }
        Files.writeString(priv, pem("PRIVATE KEY", kp.getPrivate().getEncoded()));
        try {
            Files.setPosixFilePermissions(priv, PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException ignored) {
            // non-POSIX file system
        }
        Files.writeString(pub, pem("PUBLIC KEY", kp.getPublic().getEncoded()));
        log.warn("generated a new signing key at {} — nodes need {} to accept warrants", priv, pub);
    }

    private static byte[] readPem(Path p) throws IOException {
        String body = Files.readString(p, StandardCharsets.US_ASCII)
                .replaceAll("-----[A-Z ]+-----", "")
                .replaceAll("\\s", "");
        return Base64.getDecoder().decode(body);
    }

    private static String pem(String type, byte[] der) {
        String b64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der);
        return "-----BEGIN " + type + "-----\n" + b64 + "\n-----END " + type + "-----\n";
    }
}
