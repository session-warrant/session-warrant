-- 노드 폐기. 유출된 인증서(또는 dev 신원)로 붙는 노드를 서버가 거부한다 — CRL 의 작은 대역이다.
-- 노드 인증서를 믿는 곳이 이 서버 하나뿐이라, 인증서 지문(client_cert_fingerprint)을 막으면 같은 효과가 난다.
-- 되돌리지 않는다. 다시 붙이려면 새 인증서를 발급한다(새 지문 = 새 노드 행).
ALTER TABLE node
    ADD COLUMN revoked_at    TIMESTAMPTZ,
    ADD COLUMN revoked_by    UUID REFERENCES subject (id),
    ADD COLUMN revoke_reason TEXT;
