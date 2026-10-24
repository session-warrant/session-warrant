// Package upstream 은 중앙 gRPC 클라이언트다 (mTLS). 끊겨도 커널의 집행은 계속된다.
//
// 하는 일:
//   - Dial · Heartbeat: 중앙에 붙고 살아 있음을 알린다
//   - Subscribe: 영장 push 를 받아 Applier 로 넘긴다
//   - Verify · ToKernel: 서명을 검증하고, 절대시각을 노드 boot 기준 맵 값으로 바꾼다
//   - LookupActiveWarrant: PAM 세션의 계정 · 지문으로 영장을 찾는다
//   - StreamAudit · RequestExtension: 감사 이벤트를 올리고 연장을 요청한다
//
// 부르는 쪽: cmd/warrantd 기동 5단계, binder.
// 상태: Dial(평문 전용) · StreamAudit 구현. mTLS 와 나머지는 미구현 (B 담당).
package upstream

import (
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"

	"github.com/session-warrant/session-warrant/agent/internal/bpfmap"
	"github.com/session-warrant/session-warrant/agent/internal/pb"
)

type Client struct {
	conn       *grpc.ClientConn
	audit      pb.AuditIngestServiceClient
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

// Dial does not block; the first RPC connects. Empty cert paths mean plaintext, for local development only.
func Dial(endpoint string, certPath, keyPath, caPath string) (*Client, error) {
	if certPath != "" || keyPath != "" || caPath != "" {
		return nil, errors.New("upstream: mTLS is not implemented yet")
	}
	return dial(endpoint,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithKeepaliveParams(keepaliveParams))
}

func dial(endpoint string, opts ...grpc.DialOption) (*Client, error) {
	conn, err := grpc.NewClient(endpoint, opts...)
	if err != nil {
		return nil, fmt.Errorf("upstream: dial %s: %w", endpoint, err)
	}
	return &Client{
		conn:       conn,
		audit:      pb.NewAuditIngestServiceClient(conn),
		minBackoff: time.Second,
		maxBackoff: 30 * time.Second,
	}, nil
}

func (c *Client) Close() error {
	return c.conn.Close()
}

// Subscribe 는 활성 집합 전체 → ResyncComplete → 변경분 순으로 받는다.
// ResyncComplete 에서 집합 밖의 캐시 영장을 지운다.
func (c *Client) Subscribe(ctx context.Context, apply Applier) error {
	panic("미구현")
}

// Applier 는 검증 → 저장 → 맵 순서로 반영한다.
type Applier interface {
	Apply(ctx context.Context, signedEnvelope []byte) error
}

// Verify 는 하나라도 어기면 적용하지 않는다:
//  1. Ed25519 서명 (key_id 로 고른 키, 받은 바이트 그대로)
//  2. target_hosts 에 자기 hostname 이 있다
//  3. revision 이 가진 것보다 크다
//  4. 같은 policy_id 에 다른 정책 내용이 오지 않았다
//  5. break_glass 면 즉시 최고 등급 경보
func Verify(signedEnvelope []byte, hostname string, knownRevision uint32) error {
	panic("미구현")
}

// ToKernel 은 절대시각을 노드 boot 기준으로 바꾼다. 이 변환은 여기서만 한다.
func ToKernel(expiresAtUnixNs, graceWindowNs uint64, bootedAtUnixNs uint64) bpfmap.Warrant {
	panic("미구현")
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
