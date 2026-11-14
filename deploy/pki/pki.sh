#!/usr/bin/env bash
# 노드 ↔ 중앙 gRPC(mTLS)의 사내 CA 와 인증서. 맥(중앙 쪽)에서 만들어 노드로 옮긴다.
#
#   deploy/pki/pki.sh ca                                  # CA 하나 (처음 한 번)
#   deploy/pki/pki.sh server localhost 127.0.0.1 host.lima.internal   # 서버 인증서. 인자는 노드가 붙는 이름 · 주소
#   deploy/pki/pki.sh node lima-sw                        # 노드 인증서. CN = 호스트 이름 = 노드가 알리는 hostname
#   deploy/pki/pki.sh fingerprint .cache/pki/nodes/lima-sw.pem   # 서버가 노드 신원으로 쓰는 값
#
# 결과는 $PKI_DIR(기본 .cache/pki, git 무시)에 둔다. 노드에는 nodes/<호스트>.{pem,key} 와 ca.pem 만 보낸다 —
# ca.key 는 중앙 밖으로 내보내지 않는다. 키는 EC P-256. 서버 · 노드 인증서 기간은 $DAYS(기본 825일).
#
# 노드를 뺄 때: 서버가 신원으로 쓰는 지문(fingerprint)을 막는다. 폐기 목록(CRL)은 아직 없다.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
PKI_DIR=${PKI_DIR:-$ROOT/.cache/pki}
DAYS=${DAYS:-825}
mkdir -p "$PKI_DIR/nodes"
umask 077

key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; }

# Signs a CSR with the CA. $3 is the extension block (x509v3 config syntax).
sign() {
  local csr=$1 out=$2 ext=$3 conf
  conf=$(mktemp)
  printf '%s\n' "$ext" > "$conf"
  openssl x509 -req -in "$csr" -CA "$PKI_DIR/ca.pem" -CAkey "$PKI_DIR/ca.key" -CAcreateserial \
    -days "$DAYS" -sha256 -extfile "$conf" -out "$out" 2>/dev/null
  rm -f "$conf" "$csr"
  chmod 0644 "$out"
}

need_ca() { [ -f "$PKI_DIR/ca.key" ] || { echo "no CA in $PKI_DIR — run: $0 ca" >&2; exit 2; }; }

case "${1:-}" in
  ca)
    [ -f "$PKI_DIR/ca.key" ] && { echo "CA already exists: $PKI_DIR/ca.pem"; exit 0; }
    key "$PKI_DIR/ca.key"
    openssl req -x509 -new -key "$PKI_DIR/ca.key" -sha256 -days 3650 -subj "/O=Session Warrant/CN=Session Warrant node CA" \
      -addext "basicConstraints=critical,CA:TRUE,pathlen:0" -addext "keyUsage=critical,keyCertSign,cRLSign" \
      -out "$PKI_DIR/ca.pem"
    chmod 0644 "$PKI_DIR/ca.pem"
    echo "CA: $PKI_DIR/ca.pem"
    ;;
  server)
    need_ca; shift
    [ $# -ge 1 ] || { echo "usage: $0 server <name|ip>..." >&2; exit 2; }
    san=""
    for n in "$@"; do
      if [[ $n =~ ^[0-9.]+$ || $n == *:* ]]; then san+="IP:$n,"; else san+="DNS:$n,"; fi
    done
    key "$PKI_DIR/server.key"
    openssl req -new -key "$PKI_DIR/server.key" -subj "/O=Session Warrant/CN=$1" -out "$PKI_DIR/server.csr"
    sign "$PKI_DIR/server.csr" "$PKI_DIR/server.pem" "basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=${san%,}"
    echo "server: $PKI_DIR/server.pem (${san%,})"
    ;;
  node)
    need_ca
    host=${2:?usage: $0 node <hostname>}
    [[ $host =~ ^[A-Za-z0-9._-]+$ ]] || { echo "bad hostname: $host" >&2; exit 2; }
    key "$PKI_DIR/nodes/$host.key"
    openssl req -new -key "$PKI_DIR/nodes/$host.key" -subj "/O=Session Warrant/CN=$host" -out "$PKI_DIR/nodes/$host.csr"
    sign "$PKI_DIR/nodes/$host.csr" "$PKI_DIR/nodes/$host.pem" "basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectAltName=DNS:$host"
    echo "node: $PKI_DIR/nodes/$host.pem  fingerprint $("$0" fingerprint "$PKI_DIR/nodes/$host.pem")"
    ;;
  fingerprint)
    # Same form the server records as the node identity: sha256 of the DER certificate, lowercase hex.
    openssl x509 -in "${2:?usage: $0 fingerprint <cert.pem>}" -outform DER | openssl dgst -sha256 -r | awk '{print "sha256:" $1}'
    ;;
  *) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
