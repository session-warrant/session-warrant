package io.seswar.warrant.node;

import io.grpc.Context;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HexFormat;

/**
 * mTLS 로 붙은 노드의 인증서. {@code identity} 는 서버가 노드를 가리키는 값({@code node.client_cert_fingerprint}),
 * {@code hostname} 은 인증서 CN — 노드가 NodeHello 로 말하는 호스트 이름은 이것과 같아야 한다.
 *
 * <p>NodeTlsInterceptor 가 gRPC 호출마다 {@link Context} 에 싣는다. 평문 연결(dev · 테스트)이면 없다.
 */
public record NodePeer(String identity, String hostname) {

    private static final Context.Key<NodePeer> KEY = Context.key("warrant-node-peer");

    /** 지금 gRPC 호출의 노드 인증서. 평문 연결이면 null. */
    public static NodePeer current() {
        return KEY.get();
    }

    public Context attach(Context ctx) {
        return ctx.withValue(KEY, this);
    }

    // Called by NodeTlsInterceptor with the client's leaf certificate. Same form as deploy/pki/pki.sh fingerprint.
    public static NodePeer of(X509Certificate cert) {
        try {
            String fp = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(cert.getEncoded()));
            return new NodePeer("sha256:" + fp, commonName(cert));
        } catch (NoSuchAlgorithmException | CertificateEncodingException e) {
            throw new IllegalStateException("cannot fingerprint node certificate", e);
        }
    }

    private static String commonName(X509Certificate cert) {
        try {
            for (Rdn rdn : new LdapName(cert.getSubjectX500Principal().getName()).getRdns()) {
                if (rdn.getType().equalsIgnoreCase("CN")) {
                    return rdn.getValue().toString();
                }
            }
            return null;
        } catch (InvalidNameException e) {
            return null;
        }
    }
}
