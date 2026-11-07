package upstream

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"

	"github.com/session-warrant/session-warrant/agent/internal/pb"
)

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func sign(t *testing.T, priv ed25519.PrivateKey, keyID string, w *pb.Warrant) *pb.SignedWarrant {
	t.Helper()
	b, err := proto.Marshal(w)
	if err != nil {
		t.Fatal(err)
	}
	return &pb.SignedWarrant{Warrant: b, Signature: ed25519.Sign(priv, b), KeyId: keyID}
}

// 서명은 받은 바이트 그대로에 대해 검증한다. 한 바이트라도 바뀌면 거부한다.
func TestVerify(t *testing.T) {
	pub, priv := newKey(t)
	keys := TrustKeys{"k1": pub}
	w := &pb.Warrant{WarrantId: 9, Revision: 2}

	got, err := Verify(sign(t, priv, "k1", w), keys)
	if err != nil {
		t.Fatal(err)
	}
	if got.GetWarrantId() != 9 || got.GetRevision() != 2 {
		t.Fatalf("parsed %v", got)
	}

	bad := map[string]func(*pb.SignedWarrant){
		"모르는 키":     func(e *pb.SignedWarrant) { e.KeyId = "k2" },
		"영장 바이트 변조": func(e *pb.SignedWarrant) { e.Warrant = append([]byte{}, e.Warrant...); e.Warrant[0] ^= 1 },
		"서명 변조":     func(e *pb.SignedWarrant) { e.Signature[0] ^= 1 },
		"서명 길이":     func(e *pb.SignedWarrant) { e.Signature = e.Signature[:10] },
		"서명 없음":     func(e *pb.SignedWarrant) { e.Signature = nil },
	}
	for name, mutate := range bad {
		t.Run(name, func(t *testing.T) {
			e := sign(t, priv, "k1", w)
			mutate(e)
			if _, err := Verify(e, keys); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// 다른 키로 서명한 영장은 key_id 가 맞아도 거부한다.
func TestVerifyRejectsOtherSigner(t *testing.T) {
	pub, _ := newKey(t)
	_, other := newKey(t)
	if _, err := Verify(sign(t, other, "k1", &pb.Warrant{WarrantId: 1}), TrustKeys{"k1": pub}); err == nil {
		t.Fatal("accepted a warrant signed by another key")
	}
}

func writePEM(t *testing.T, path string, pub any) {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
}

// 키 파일은 JDK 의 PublicKey.getEncoded() 형식(PKIX)을 PEM 으로 감싼 것이다. 파일 이름이 key_id 다.
func TestLoadTrustKeys(t *testing.T) {
	dir := t.TempDir()
	pub, _ := newKey(t)
	writePEM(t, filepath.Join(dir, "central-2026.pem"), pub)
	os.WriteFile(filepath.Join(dir, "README"), []byte("not a key"), 0o644)

	keys, err := LoadTrustKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || !keys["central-2026"].Equal(pub) {
		t.Fatalf("keys %v", keys)
	}
}

// Ed25519 가 아닌 키가 섞여 있으면 조용히 건너뛰지 않고 실패한다.
func TestLoadTrustKeysRejectsOtherKeyTypes(t *testing.T) {
	dir := t.TempDir()
	writePEM(t, filepath.Join(dir, "k.pem"), &ecdsaKey(t).PublicKey)
	if _, err := LoadTrustKeys(dir); err == nil {
		t.Fatal("accepted a non-Ed25519 key")
	}
}

func ecdsaKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

type pushStream = grpc.ServerStreamingServer[pb.PushMessage]

// Fake central push service. handle decides what each stream (numbered from 1) does.
type fakePush struct {
	pb.UnimplementedWarrantPushServiceServer
	mu      sync.Mutex
	streams int
	reqs    []*pb.SubscribeRequest
	handle  func(n int, st pushStream) error
}

func (f *fakePush) Subscribe(req *pb.SubscribeRequest, st pushStream) error {
	f.mu.Lock()
	f.streams++
	n := f.streams
	f.reqs = append(f.reqs, req)
	f.mu.Unlock()
	return f.handle(n, st)
}

func startPush(t *testing.T, f *fakePush) *Client {
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
	c.minBackoff, c.maxBackoff = 10*time.Millisecond, 20*time.Millisecond
	t.Cleanup(func() { c.Close() })
	return c
}

// Records what Subscribe hands over. reject makes Apply fail for that warrant id.
type fakeApplier struct {
	mu      sync.Mutex
	applied []uint64
	reject  map[uint64]bool
	resyncs chan map[uint64]struct{}
}

func newApplier() *fakeApplier {
	return &fakeApplier{resyncs: make(chan map[uint64]struct{}, 4)}
}

func (a *fakeApplier) Apply(env *pb.SignedWarrant) (uint64, error) {
	w := &pb.Warrant{}
	if err := proto.Unmarshal(env.GetWarrant(), w); err != nil {
		return 0, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.reject[w.GetWarrantId()] {
		return 0, errors.New("bad signature")
	}
	a.applied = append(a.applied, w.GetWarrantId())
	return w.GetWarrantId(), nil
}

func (a *fakeApplier) Resync(active map[uint64]struct{}) { a.resyncs <- active }

func (a *fakeApplier) Revisions() map[uint64]uint32 { return map[uint64]uint32{9: 3} }

func pushWarrant(st pushStream, id uint64) error {
	b, _ := proto.Marshal(&pb.Warrant{WarrantId: id})
	return st.Send(&pb.PushMessage{Body: &pb.PushMessage_Warrant{Warrant: &pb.SignedWarrant{Warrant: b}}})
}

func pushResync(st pushStream, n uint32) error {
	return st.Send(&pb.PushMessage{Body: &pb.PushMessage_ResyncComplete{ResyncComplete: &pb.ResyncComplete{ActiveCount: n}}})
}

func waitResync(t *testing.T, a *fakeApplier) map[uint64]struct{} {
	t.Helper()
	select {
	case got := <-a.resyncs:
		return got
	case <-time.After(5 * time.Second):
		t.Fatal("no resync")
		return nil
	}
}

// 활성 집합 → ResyncComplete 순서로 오면, 그 스트림에서 받은 id 전부로 Resync 한다.
func TestSubscribeAppliesPushesThenResyncs(t *testing.T) {
	f := &fakePush{handle: func(_ int, st pushStream) error {
		pushWarrant(st, 9)
		pushWarrant(st, 11)
		pushResync(st, 2)
		<-st.Context().Done()
		return nil
	}}
	c := startPush(t, f)
	a := newApplier()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Subscribe(ctx, hello(), a)

	got := waitResync(t, a)
	if _, ok := got[9]; !ok || len(got) != 2 {
		t.Fatalf("resync set %v, want {9, 11}", got)
	}
	f.mu.Lock()
	req := f.reqs[0]
	f.mu.Unlock()
	if req.GetNode().GetHostname() != "node-a" || req.GetCachedRevisions()[9] != 3 {
		t.Fatalf("subscribe request %v", req)
	}
}

// 검증에 실패한 영장은 활성 집합에 넣지 않는다 — 서명 없는 메시지로 영장을 살려 둘 수 없어야 한다.
func TestSubscribeLeavesRejectedPushesOutOfResync(t *testing.T) {
	f := &fakePush{handle: func(_ int, st pushStream) error {
		pushWarrant(st, 9)
		pushWarrant(st, 13)
		pushResync(st, 2)
		<-st.Context().Done()
		return nil
	}}
	c := startPush(t, f)
	a := newApplier()
	a.reject = map[uint64]bool{13: true}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Subscribe(ctx, hello(), a)

	if got := waitResync(t, a); len(got) != 1 {
		t.Fatalf("resync set %v, want {9}", got)
	}
}

// 스트림이 끊기면 다시 구독하고, 새 스트림은 처음부터 활성 집합을 다시 받는다.
func TestSubscribeReconnectsAfterStreamEnds(t *testing.T) {
	f := &fakePush{handle: func(n int, st pushStream) error {
		if n == 1 {
			pushWarrant(st, 9)
			return errors.New("server restarting") // no resync on this stream
		}
		pushWarrant(st, 9)
		pushResync(st, 1)
		<-st.Context().Done()
		return nil
	}}
	c := startPush(t, f)
	a := newApplier()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Subscribe(ctx, hello(), a)

	waitResync(t, a)
	f.mu.Lock()
	n := f.streams
	f.mu.Unlock()
	if n != 2 {
		t.Fatalf("streams %d, want 2", n)
	}
}

// 스트림이 열려 있는 동안 오는 변경분도 바로 적용한다. Resync 는 스트림마다 한 번이다.
func TestSubscribeAppliesChangesAfterResync(t *testing.T) {
	sent := make(chan struct{})
	f := &fakePush{handle: func(_ int, st pushStream) error {
		pushResync(st, 0)
		pushWarrant(st, 21)
		close(sent)
		<-st.Context().Done()
		return nil
	}}
	c := startPush(t, f)
	a := newApplier()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Subscribe(ctx, hello(), a)

	if got := waitResync(t, a); len(got) != 0 {
		t.Fatalf("resync set %v, want empty", got)
	}
	<-sent
	deadline := time.Now().Add(5 * time.Second)
	for {
		a.mu.Lock()
		n := len(a.applied)
		a.mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("change after resync was not applied")
		}
		time.Sleep(5 * time.Millisecond)
	}
	select {
	case got := <-a.resyncs:
		t.Fatalf("second resync %v on the same stream", got)
	default:
	}
}
