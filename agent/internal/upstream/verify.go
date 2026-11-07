package upstream

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/session-warrant/session-warrant/agent/internal/pb"
)

// TrustKeys are the central signing keys by key_id. Two can coexist during a key rotation.
type TrustKeys map[string]ed25519.PublicKey

// LoadTrustKeys reads <key_id>.pem files: a PKIX "PUBLIC KEY", the form JDK's PublicKey.getEncoded() gives.
func LoadTrustKeys(dir string) (TrustKeys, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.pem"))
	if err != nil {
		return nil, err
	}
	keys := TrustKeys{}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		blk, _ := pem.Decode(b)
		if blk == nil || blk.Type != "PUBLIC KEY" {
			return nil, fmt.Errorf("%s: not a PEM PUBLIC KEY", p)
		}
		k, err := x509.ParsePKIXPublicKey(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		ek, ok := k.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%s: %T is not Ed25519", p, k)
		}
		keys[strings.TrimSuffix(filepath.Base(p), ".pem")] = ek
	}
	return keys, nil
}

// Verify checks the signature over the received bytes as they are, then parses them.
// Host, revision and policy checks need node state; the Applier does those.
func Verify(env *pb.SignedWarrant, keys TrustKeys) (*pb.Warrant, error) {
	key, ok := keys[env.GetKeyId()]
	if !ok {
		return nil, fmt.Errorf("unknown key_id %q", env.GetKeyId())
	}
	if len(env.GetSignature()) != ed25519.SignatureSize {
		return nil, fmt.Errorf("signature is %d bytes", len(env.GetSignature()))
	}
	if !ed25519.Verify(key, env.GetWarrant(), env.GetSignature()) {
		return nil, errors.New("bad signature")
	}
	w := &pb.Warrant{}
	if err := proto.Unmarshal(env.GetWarrant(), w); err != nil {
		return nil, fmt.Errorf("signed bytes are not a Warrant: %w", err)
	}
	return w, nil
}
