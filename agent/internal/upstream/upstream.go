// Package upstream 은 중앙 gRPC 클라이언트다 (mTLS). 끊겨도 커널의 집행은 계속된다.
//
// 하는 일:
//   - Dial · Heartbeat: 중앙에 붙고 살아 있음을 알린다
//   - Subscribe (subscribe.go): 영장 push 를 받아 Applier 로 넘긴다. 끊기면 다시 붙는다
//   - Verify · LoadTrustKeys (verify.go): 받은 바이트 그대로 Ed25519 서명을 검증한다
//   - LookupActiveWarrant: PAM 세션의 계정 · 지문으로 영장을 찾는다
//   - StreamAudit · RequestExtension: 감사 이벤트를 올리고 연장을 요청한다
//
// boot 기준 시각 변환 · 정책 컴파일 · 맵 쓰기는 여기서 하지 않는다 — Applier(cmd/warrantd)가 한다.
//
// 부르는 쪽: cmd/warrantd 기동 5단계, binder.
// 상태: Dial(mTLS · 로컬 개발용 평문) · StreamAudit · Subscribe · Verify 구현. Heartbeat · 연장 · Lookup 은 미구현.
package upstream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"

	"github.com/session-warrant/session-warrant/agent/internal/pb"
)

type Client struct {
	conn       *grpc.ClientConn
	audit      pb.AuditIngestServiceClient
	push       pb.WarrantPushServiceClient
	minBackoff time.Duration
	maxBackoff time.Duration
}

// Pings an idle connection so a dead peer is noticed. Pairs with the server's
// spring.grpc.server.keepalive.permit.time, which must be <= Time or the server drops us (too_many_pings).
var keepaliveParams = keepalive.ClientParameters{
	Time:                30 * time.Second,
	Timeout:             10 * time.Second,
	PermitWithoutStream: true,
}

// Dial does not block; the first RPC connects. With the node certificate, its key and the CA it is mTLS: the
// central server knows the node by that certificate. All three empty means plaintext, for local development only.
func Dial(endpoint string, certPath, keyPath, caPath string) (*Client, error) {
	creds := insecure.NewCredentials()
	if certPath != "" || keyPath != "" || caPath != "" {
		var err error
		if creds, err = nodeTLS(certPath, keyPath, caPath); err != nil {
			return nil, err
		}
	}
	return dial(endpoint, grpc.WithTransportCredentials(creds), grpc.WithKeepaliveParams(keepaliveParams))
}

// Half a TLS setup must not quietly fall back to plaintext. The server name checked is the endpoint's host.
func nodeTLS(certPath, keyPath, caPath string) (credentials.TransportCredentials, error) {
	if certPath == "" || keyPath == "" || caPath == "" {
		return nil, errors.New("upstream: mTLS needs the node certificate, its key and the CA together")
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("upstream: node certificate: %w", err)
	}
	ca, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("upstream: CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("upstream: CA: no certificate in %s", caPath)
	}
	return credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool, MinVersion: tls.VersionTLS12}), nil
}

func dial(endpoint string, opts ...grpc.DialOption) (*Client, error) {
	conn, err := grpc.NewClient(endpoint, opts...)
	if err != nil {
		return nil, fmt.Errorf("upstream: dial %s: %w", endpoint, err)
	}
	return &Client{
		conn:       conn,
		audit:      pb.NewAuditIngestServiceClient(conn),
		push:       pb.NewWarrantPushServiceClient(conn),
		minBackoff: time.Second,
		maxBackoff: 30 * time.Second,
	}, nil
}

func (c *Client) Close() error {
	return c.conn.Close()
}

func (c *Client) Heartbeat(ctx context.Context) error {
	panic("미구현")
}

func (c *Client) RequestExtension(ctx context.Context, warrantID uint64, detectedWorkload string, ns uint64) error {
	panic("미구현")
}

// LookupActiveWarrant 는 캐시가 비었을 때만 부른다. 타임아웃이면 fail-open.
func (c *Client) LookupActiveWarrant(ctx context.Context, loginAccount, fingerprint string) ([][]byte, error) {
	panic("미구현")
}
