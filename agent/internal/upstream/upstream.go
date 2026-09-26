// Package upstream 은 중앙 gRPC 클라이언트다 (mTLS). 끊겨도 커널의 집행은 계속된다.
package upstream

import (
	"context"

	"github.com/session-warrant/session-warrant/agent/internal/bpfmap"
)

type Client struct{}

func Dial(endpoint string, certPath, keyPath, caPath string) (*Client, error) {
	panic("미구현")
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

func (c *Client) StreamAudit(ctx context.Context, s AuditSource) error {
	panic("미구현")
}

type AuditSource interface {
	Next(ctx context.Context) (batch []byte, err error)
	Ack(seqEpoch, nodeSeq uint64) error
}
