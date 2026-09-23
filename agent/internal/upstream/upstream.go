// Package upstream 은 중앙 gRPC 클라이언트다. mTLS.
//
// B(서버·계약) 소유. 이 패키지가 끊겨도 커널의 집행은 계속된다 —
// 판정 시점에 유저 공간으로 올라오는 왕복은 하나도 없다(§10, §17).
package upstream

import (
	"context"

	"github.com/session-warrant/session-warrant/agent/internal/bpfmap"
)

// Client 는 중앙과의 연결이다.
type Client struct{}

func Dial(endpoint string, certPath, keyPath, caPath string) (*Client, error) {
	panic("미구현")
}

// Subscribe 는 활성 집합 전체 → ResyncComplete → 이후 변경분을 받는다.
// ResyncComplete 에서 집합 밖의 캐시 영장을 지운다.
func (c *Client) Subscribe(ctx context.Context, apply Applier) error {
	panic("미구현")
}

// Applier 는 받은 봉투를 검증해 맵에 반영한다. 순서는 검증 → 저장 → 맵이다.
type Applier interface {
	Apply(ctx context.Context, signedEnvelope []byte) error
}

// Verify 는 봉투를 받았을 때 반드시 거치는 관문이다. 하나라도 어기면 적용하지 않는다.
//
//  1. Ed25519 서명 — key_id 로 고른 공개키로. 받은 바이트 그대로 검증한다
//  2. target_hosts 에 자기 hostname 이 있는가 — 잘못 배달된 영장 방어
//  3. revision 이 자기가 가진 것보다 큰가 — 취소 뒤 옛 봉투를 다시 미는 재생 방어
//  4. policy_id 가 같은데 정책 내용이 다르면 거부하고 경보 — rule_* 맵이 서로 덮어쓴다
//  5. break_glass 면 즉시 최고 등급 경보
func Verify(signedEnvelope []byte, hostname string, knownRevision uint32) error {
	panic("미구현")
}

// ToKernel 은 절대시각(Unix ns)을 노드 boot 기준으로 바꿔 맵 값을 만든다.
//
// 이 변환은 warrantd 에서만 한다. proto 에도 서버 DB 에도 boot 기준 값을 넣지 않는다 —
// 노드마다 기준이 다르고, 중앙이 계산하면 시계 스큐가 그대로 만료 오차가 된다.
func ToKernel(expiresAtUnixNs, graceWindowNs uint64, bootedAtUnixNs uint64) bpfmap.Warrant {
	panic("미구현")
}

// Heartbeat 는 활성 영장 수와 ringbuf 드롭 누적을 올린다.
// 서버가 기대하는 수와 어긋나면 재구독한다.
func (c *Client) Heartbeat(ctx context.Context) error {
	panic("미구현")
}

// RequestExtension 은 T-5 분 자동 연장 요청이다. 결과는 새 revision push 로 온다.
func (c *Client) RequestExtension(ctx context.Context, warrantID uint64, detectedWorkload string, ns uint64) error {
	panic("미구현")
}

// LookupActiveWarrant 는 캐시가 비었을 때만 부른다.
// 타임아웃이면 fail-open — 로그인을 허용하고 무영장으로 기록한다.
// 중앙이 인증 경로에 끼면 중앙 장애가 곧 로그인 장애가 된다.
func (c *Client) LookupActiveWarrant(ctx context.Context, loginAccount, fingerprint string) ([][]byte, error) {
	panic("미구현")
}

// StreamAudit 는 양방향 스트리밍이다. 서버 ack 를 받아 store 를 비운다.
func (c *Client) StreamAudit(ctx context.Context, s AuditSource) error {
	panic("미구현")
}

// AuditSource 는 올려보낼 배치를 공급한다.
type AuditSource interface {
	Next(ctx context.Context) (batch []byte, err error)
	Ack(seqEpoch, nodeSeq uint64) error
}
