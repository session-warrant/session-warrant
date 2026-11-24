package upstream

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/session-warrant/session-warrant/agent/internal/pb"
)

// Fake central for the unary node calls.
type fakeNode struct {
	pb.UnimplementedWarrantPushServiceServer
	mu       sync.Mutex
	beats    []*pb.HeartbeatRequest
	expected uint32
	fail     bool
	lookups  []*pb.LookupRequest
	found    []*pb.SignedWarrant
}

func (f *fakeNode) Heartbeat(_ context.Context, req *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.beats = append(f.beats, req)
	if f.fail {
		return nil, status.Error(codes.Unavailable, "down")
	}
	return &pb.HeartbeatResponse{ExpectedActiveWarrants: f.expected}, nil
}

func (f *fakeNode) LookupActiveWarrant(_ context.Context, req *pb.LookupRequest) (*pb.LookupResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lookups = append(f.lookups, req)
	return &pb.LookupResponse{Warrants: f.found}, nil
}

func (f *fakeNode) beatCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.beats)
}

func startNode(t *testing.T, f *fakeNode) *Client {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	pb.RegisterWarrantPushServiceServer(srv, f)
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)

	c, err := dial("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// 생존 신호는 노드 정보 · 커널 맵의 영장 수 · ringbuf 유실 누적을 싣고, 서버가 기대하는 수를 돌려받는다.
func TestHeartbeatSendsStateAndReturnsExpected(t *testing.T) {
	f := &fakeNode{expected: 3}
	c := startNode(t, f)

	got, err := c.Heartbeat(context.Background(), &pb.NodeHello{Hostname: "n1"}, 2, 17)
	if err != nil {
		t.Fatal(err)
	}
	if got != 3 {
		t.Fatalf("expected = %d, want 3", got)
	}
	r := f.beats[0]
	if r.GetNode().GetHostname() != "n1" || r.GetActiveWarrants() != 2 || r.GetRingbufDroppedTotal() != 17 {
		t.Fatalf("request = %v", r)
	}
}

// 수가 어긋나면 mismatch 를 부른다 — warrantd 는 거기서 다시 구독한다.
func TestHeartbeatLoopReportsMismatch(t *testing.T) {
	f := &fakeNode{expected: 5}
	c := startNode(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	got := make(chan [2]uint32, 1)
	go c.HeartbeatLoop(ctx, 10*time.Millisecond, &pb.NodeHello{Hostname: "n1"},
		func() (uint32, uint64) { return 4, 0 },
		func(expected, have uint32) {
			select {
			case got <- [2]uint32{expected, have}:
			default:
			}
		})

	select {
	case m := <-got:
		if m != [2]uint32{5, 4} {
			t.Fatalf("mismatch(%d, %d), want (5, 4)", m[0], m[1])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("mismatch was not reported")
	}
}

// 수가 맞으면 아무 일도 없다.
func TestHeartbeatLoopQuietWhenCountsMatch(t *testing.T) {
	f := &fakeNode{expected: 4}
	c := startNode(t, f)
	ctx, cancel := context.WithCancel(context.Background())

	called := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		done <- c.HeartbeatLoop(ctx, 10*time.Millisecond, &pb.NodeHello{Hostname: "n1"},
			func() (uint32, uint64) { return 4, 0 },
			func(uint32, uint32) { called <- struct{}{} })
	}()
	for f.beatCount() < 3 {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	select {
	case <-called:
		t.Fatal("mismatch called although counts match")
	default:
	}
}

// 서버가 죽어 있어도 루프는 멈추지 않는다 — 다음 주기에 다시 보낸다.
func TestHeartbeatLoopSurvivesServerErrors(t *testing.T) {
	f := &fakeNode{fail: true}
	c := startNode(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go c.HeartbeatLoop(ctx, 10*time.Millisecond, &pb.NodeHello{Hostname: "n1"},
		func() (uint32, uint64) { return 0, 0 }, nil)

	deadline := time.Now().Add(2 * time.Second)
	for f.beatCount() < 3 {
		if time.Now().After(deadline) {
			t.Fatalf("only %d heartbeats after errors", f.beatCount())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// 조회는 세 값을 그대로 보내고 받은 봉투를 그대로 돌려준다(검증은 부르는 쪽이 Verify 로).
func TestLookupActiveWarrant(t *testing.T) {
	env := &pb.SignedWarrant{Warrant: []byte("w"), Signature: []byte("s"), KeyId: "central"}
	f := &fakeNode{found: []*pb.SignedWarrant{env}}
	c := startNode(t, f)

	got, err := c.LookupActiveWarrant(context.Background(), "n1", "ec2-user", "SHA256:abc")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || string(got[0].GetWarrant()) != "w" || got[0].GetKeyId() != "central" {
		t.Fatalf("got %v", got)
	}
	r := f.lookups[0]
	if r.GetHostname() != "n1" || r.GetLoginAccount() != "ec2-user" || r.GetSshKeyFingerprint() != "SHA256:abc" {
		t.Fatalf("request = %v", r)
	}
}
