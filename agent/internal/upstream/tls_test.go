package upstream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"github.com/session-warrant/session-warrant/agent/internal/pb"
)

// Test certificates come from deploy/pki/pki.sh (copied from server/src/test/resources/mtls): CA, server for
// localhost, node "node-a".

// A TLS server that, like the central one, only lets in clients holding a certificate from the test CA.
// It reports the client certificate's CN for each stream.
func startTLS(t *testing.T) (addr string, seen chan string) {
	t.Helper()
	cert, err := tls.LoadX509KeyPair("testdata/server.pem", "testdata/server.key")
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := os.ReadFile("testdata/ca.pem")
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert,
	})))
	seen = make(chan string, 1)
	pb.RegisterAuditIngestServiceServer(srv, &fakeIngest{handle: func(_ int, st stream) error {
		p, _ := peer.FromContext(st.Context())
		info := p.AuthInfo.(credentials.TLSInfo)
		seen <- info.State.PeerCertificates[0].Subject.CommonName
		_, err := st.Recv()
		return err
	}})
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)
	return "localhost:" + strings.Split(lis.Addr().String(), ":")[1], seen
}

// 중앙은 노드 인증서로 노드를 가린다. warrantd 가 그 인증서를 들고 TLS 로 붙어야 한다.
func TestDialWithNodeCertificateReachesTheCentralServer(t *testing.T) {
	addr, seen := startTLS(t)
	c, err := Dial(addr, "testdata/node-a.pem", "testdata/node-a.key", "testdata/ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := c.audit.Stream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Send(&pb.AuditBatch{SeqEpoch: 1, Node: hello()}); err != nil {
		t.Fatal(err)
	}
	select {
	case cn := <-seen:
		if cn != "node-a" {
			t.Fatalf("server saw client %q", cn)
		}
	case <-ctx.Done():
		t.Fatal("server never saw the node certificate")
	}
}

// 반쪽 설정(인증서만 · CA 만)으로 조용히 평문이 되면 안 된다.
func TestDialRefusesPartialTLSSettings(t *testing.T) {
	for _, c := range [][3]string{
		{"testdata/node-a.pem", "", ""},
		{"testdata/node-a.pem", "testdata/node-a.key", ""},
		{"", "", "testdata/ca.pem"},
	} {
		if _, err := Dial("localhost:9090", c[0], c[1], c[2]); err == nil {
			t.Errorf("Dial accepted cert=%q key=%q ca=%q", c[0], c[1], c[2])
		}
	}
}

func TestDialRefusesUnreadableCA(t *testing.T) {
	bad := t.TempDir() + "/ca.pem"
	os.WriteFile(bad, []byte("not a certificate"), 0o600)
	if _, err := Dial("localhost:9090", "testdata/node-a.pem", "testdata/node-a.key", bad); err == nil {
		t.Fatal("Dial accepted a CA file with no certificate")
	}
}
