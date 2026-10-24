package upstream

import (
	"context"
	"errors"
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
	"github.com/session-warrant/session-warrant/agent/internal/store"
)

type stream = grpc.BidiStreamingServer[pb.AuditBatch, pb.AuditAck]

// Fake central server. handle decides what each stream (numbered from 1) does.
type fakeIngest struct {
	pb.UnimplementedAuditIngestServiceServer
	mu      sync.Mutex
	streams int
	handle  func(n int, st stream) error
}

func (f *fakeIngest) Stream(st stream) error {
	f.mu.Lock()
	f.streams++
	n := f.streams
	f.mu.Unlock()
	return f.handle(n, st)
}

func start(t *testing.T, f *fakeIngest) *Client {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	pb.RegisterAuditIngestServiceServer(srv, f)
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)

	c, err := dial("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	c.minBackoff, c.maxBackoff = 10*time.Millisecond, 20*time.Millisecond
	t.Cleanup(func() { c.Close() })
	return c
}

func hello() *pb.NodeHello {
	return &pb.NodeHello{Hostname: "node-a", AgentVersion: "warrantd test"}
}

func event() *pb.AuditEvent {
	return &pb.AuditEvent{WallTsUnixNs: 1, Hook: pb.Hook_HOOK_AGENT, Origin: pb.Origin_ORIGIN_AGENT}
}

// ackAll acks every batch and forwards it to got.
func ackAll(got chan<- *pb.AuditBatch) func(int, stream) error {
	return func(_ int, st stream) error {
		for {
			b, err := st.Recv()
			if err != nil {
				return nil
			}
			got <- b
			if err := st.Send(&pb.AuditAck{SeqEpoch: b.GetSeqEpoch(), AckedThroughNodeSeq: b.GetLastNodeSeq()}); err != nil {
				return err
			}
		}
	}
}

func run(t *testing.T, c *Client, q *store.AuditQueue) (stop func() error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.StreamAudit(ctx, hello(), q) }()
	return func() error {
		cancel()
		select {
		case err := <-done:
			return err
		case <-time.After(5 * time.Second):
			t.Fatal("StreamAudit did not return after cancel")
			return nil
		}
	}
}

func recv(t *testing.T, got <-chan *pb.AuditBatch) *pb.AuditBatch {
	t.Helper()
	select {
	case b := <-got:
		return b
	case <-time.After(5 * time.Second):
		t.Fatal("server got no batch")
		return nil
	}
}

// Waits until the queue has nothing left to send from the start, i.e. everything was acked.
func waitDrained(t *testing.T, q *store.AuditQueue) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		_, err := q.Next(ctx, 0)
		cancel()
		if errors.Is(err, context.DeadlineExceeded) {
			return
		}
	}
	t.Fatal("queue still holds events: acks were not applied")
}

func TestStreamAuditSendsHelloFirstAndDeletesAcked(t *testing.T) {
	got := make(chan *pb.AuditBatch, 10)
	c := start(t, &fakeIngest{handle: ackAll(got)})
	q := store.NewAuditQueue(100, 100)
	q.Append(event())
	q.Append(event())
	stop := run(t, c, q)

	first := recv(t, got)
	if first.GetNode().GetHostname() != "node-a" {
		t.Fatalf("first batch has no NodeHello: %v", first.GetNode())
	}
	if first.GetSeqEpoch() != q.SeqEpoch() || first.GetLastNodeSeq() != 2 {
		t.Fatalf("first batch epoch %d last %d", first.GetSeqEpoch(), first.GetLastNodeSeq())
	}
	waitDrained(t, q)

	q.Append(event())
	second := recv(t, got)
	if second.GetNode() != nil {
		t.Fatalf("NodeHello repeated on the same stream: %v", second.GetNode())
	}
	if second.GetLastNodeSeq() != 3 {
		t.Fatalf("second batch last %d, want 3", second.GetLastNodeSeq())
	}
	if err := stop(); !errors.Is(err, context.Canceled) {
		t.Fatalf("StreamAudit returned %v, want context.Canceled", err)
	}
}

// 서버가 저장 못 하고 끊으면 다시 붙어서 NodeHello 와 함께 처음부터 다시 보낸다.
func TestStreamAuditReconnectsAndResendsUnacked(t *testing.T) {
	got := make(chan *pb.AuditBatch, 10)
	acking := ackAll(got)
	c := start(t, &fakeIngest{handle: func(n int, st stream) error {
		if n == 1 {
			b, _ := st.Recv()
			got <- b
			return status.Error(codes.Unavailable, "db down") // no ack
		}
		return acking(n, st)
	}})
	q := store.NewAuditQueue(100, 100)
	q.Append(event())
	q.Append(event())
	stop := run(t, c, q)
	defer stop()

	lost := recv(t, got)
	again := recv(t, got)
	if again.GetNode() == nil {
		t.Fatal("first batch of the new stream has no NodeHello")
	}
	if again.GetLastNodeSeq() != lost.GetLastNodeSeq() || len(again.GetEvents()) != 2 {
		t.Fatalf("resent last %d with %d events, want last %d with 2",
			again.GetLastNodeSeq(), len(again.GetEvents()), lost.GetLastNodeSeq())
	}
	waitDrained(t, q)
}

// Records every Ack that reaches the source.
type recordingSource struct {
	*store.AuditQueue
	mu   sync.Mutex
	acks [][2]uint64
}

func (r *recordingSource) Ack(seqEpoch, nodeSeq uint64) error {
	r.mu.Lock()
	r.acks = append(r.acks, [2]uint64{seqEpoch, nodeSeq})
	r.mu.Unlock()
	return r.AuditQueue.Ack(seqEpoch, nodeSeq)
}

// 다른 세대의 ack 를 믿고 지우면 아직 안 보낸 기록이 사라진다. 큐에 넘기지도 않는다.
func TestStreamAuditIgnoresAckOfOtherEpoch(t *testing.T) {
	sent := make(chan struct{})
	c := start(t, &fakeIngest{handle: func(_ int, st stream) error {
		b, err := st.Recv()
		if err != nil {
			return nil
		}
		st.Send(&pb.AuditAck{SeqEpoch: b.GetSeqEpoch() + 1, AckedThroughNodeSeq: b.GetLastNodeSeq()})
		st.Send(&pb.AuditAck{SeqEpoch: b.GetSeqEpoch(), AckedThroughNodeSeq: 0}) // marks that the first was handled
		close(sent)
		<-st.Context().Done()
		return nil
	}})
	src := &recordingSource{AuditQueue: store.NewAuditQueue(100, 100)}
	src.Append(event())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.StreamAudit(ctx, hello(), src) }()
	<-sent
	deadline := time.Now().Add(5 * time.Second)
	for {
		src.mu.Lock()
		n := len(src.acks)
		src.mu.Unlock()
		if n > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done

	src.mu.Lock()
	defer src.mu.Unlock()
	if len(src.acks) != 1 || src.acks[0] != [2]uint64{src.SeqEpoch(), 0} {
		t.Fatalf("acks passed to the source = %v, want only [%d 0]", src.acks, src.SeqEpoch())
	}
}

// 오래 멀쩡하던 연결이 끊기면 바로 다시 붙는다. 보낼 게 없던 노드는 ack 를 못 받았을 뿐 정상이었다.
func TestStreamAuditRetriesQuicklyAfterALongHealthyStream(t *testing.T) {
	var mu sync.Mutex
	var endedLong, startedNext time.Time
	c := start(t, &fakeIngest{handle: func(n int, st stream) error {
		switch {
		case n <= 5: // fail at once until backoff is at its maximum
			return status.Error(codes.Unavailable, "down")
		case n == 6: // healthy and idle for longer than maxBackoff
			time.Sleep(400 * time.Millisecond)
			mu.Lock()
			endedLong = time.Now()
			mu.Unlock()
			return status.Error(codes.Unavailable, "restart")
		case n == 7:
			mu.Lock()
			startedNext = time.Now()
			mu.Unlock()
		}
		<-st.Context().Done()
		return nil
	}})
	c.minBackoff, c.maxBackoff = 10*time.Millisecond, 200*time.Millisecond
	stop := run(t, c, store.NewAuditQueue(10, 10))
	defer stop()

	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		done := !startedNext.IsZero()
		gap := startedNext.Sub(endedLong)
		mu.Unlock()
		if done {
			if gap >= 150*time.Millisecond {
				t.Fatalf("reconnected %s after a long healthy stream, want about minBackoff", gap)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("no stream after the long one")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
