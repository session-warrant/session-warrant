package store

import (
	"context"
	"testing"
	"time"

	"github.com/session-warrant/session-warrant/agent/internal/pb"
)

func ev(wallNs uint64) *pb.AuditEvent {
	return &pb.AuditEvent{WallTsUnixNs: wallNs, Hook: pb.Hook_HOOK_AGENT, Origin: pb.Origin_ORIGIN_AGENT}
}

func seqs(b *pb.AuditBatch) []uint64 {
	var out []uint64
	for _, e := range b.GetEvents() {
		out = append(out, e.GetNodeSeq())
	}
	return out
}

func equal(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// 세대 번호는 0 이면 안 된다 — 서버가 "안 채웠다"로 보고 끊는다.
func TestAuditQueueEpochIsNonZeroAndDiffersPerQueue(t *testing.T) {
	a, b := NewAuditQueue(10, 10), NewAuditQueue(10, 10)
	if a.SeqEpoch() == 0 || b.SeqEpoch() == 0 {
		t.Fatalf("epoch is 0: %d %d", a.SeqEpoch(), b.SeqEpoch())
	}
	if a.SeqEpoch() == b.SeqEpoch() {
		t.Fatalf("two queues share epoch %d", a.SeqEpoch())
	}
}

// 번호는 1 부터 하나씩. 묶음에는 세대와 마지막 번호가 실린다.
func TestAuditQueueNumbersEventsAndBatchesThem(t *testing.T) {
	q := NewAuditQueue(10, 10)
	for i := uint64(1); i <= 3; i++ {
		if got := q.Append(ev(i)); got != i {
			t.Fatalf("Append #%d returned seq %d", i, got)
		}
	}

	b, err := q.Next(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if !equal(seqs(b), []uint64{1, 2, 3}) || b.GetLastNodeSeq() != 3 || b.GetSeqEpoch() != q.SeqEpoch() {
		t.Fatalf("batch = seqs %v last %d epoch %d", seqs(b), b.GetLastNodeSeq(), b.GetSeqEpoch())
	}
}

// after 다음 것만, 그리고 묶음 크기 상한까지만.
func TestAuditQueueNextStartsAfterCursorAndCapsBatch(t *testing.T) {
	q := NewAuditQueue(10, 2)
	for i := uint64(1); i <= 5; i++ {
		q.Append(ev(i))
	}

	b, _ := q.Next(context.Background(), 1)
	if !equal(seqs(b), []uint64{2, 3}) {
		t.Fatalf("Next(after=1) = %v, want [2 3]", seqs(b))
	}
}

// 보낼 게 없으면 기다리다가, 새 기록이 들어오면 바로 돌려준다.
func TestAuditQueueNextWaitsForAppend(t *testing.T) {
	q := NewAuditQueue(10, 10)
	got := make(chan *pb.AuditBatch, 1)
	go func() {
		b, _ := q.Next(context.Background(), 0)
		got <- b
	}()

	select {
	case b := <-got:
		t.Fatalf("Next returned before any Append: %v", seqs(b))
	case <-time.After(50 * time.Millisecond):
	}
	q.Append(ev(1))
	select {
	case b := <-got:
		if !equal(seqs(b), []uint64{1}) {
			t.Fatalf("got %v", seqs(b))
		}
	case <-time.After(time.Second):
		t.Fatal("Next did not wake up after Append")
	}
}

func TestAuditQueueNextStopsOnCancel(t *testing.T) {
	q := NewAuditQueue(10, 10)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := q.Next(ctx, 0); err == nil {
		t.Fatal("Next on a cancelled context returned no error")
	}
}

// ack 받은 데까지 지운다. 다시 연결해서 처음부터 읽으면 남은 것만 나온다.
func TestAuditQueueAckDropsThroughSeq(t *testing.T) {
	q := NewAuditQueue(10, 10)
	for i := uint64(1); i <= 4; i++ {
		q.Append(ev(i))
	}
	if err := q.Ack(q.SeqEpoch(), 2); err != nil {
		t.Fatal(err)
	}
	b, _ := q.Next(context.Background(), 0)
	if !equal(seqs(b), []uint64{3, 4}) {
		t.Fatalf("after Ack(2), Next(0) = %v, want [3 4]", seqs(b))
	}
}

// 다른 세대의 ack 로 지우면 아직 안 보낸 기록이 사라진다.
func TestAuditQueueIgnoresAckOfOtherEpoch(t *testing.T) {
	q := NewAuditQueue(10, 10)
	q.Append(ev(1))
	q.Append(ev(2))
	q.Ack(q.SeqEpoch()+1, 2)

	b, _ := q.Next(context.Background(), 0)
	if !equal(seqs(b), []uint64{1, 2}) {
		t.Fatalf("ack of another epoch deleted events: Next(0) = %v", seqs(b))
	}
}

// 넘치면 오래된 것부터 버리고, 버린 구간을 다음 묶음에 유실로 싣는다. 빈 구간을 숨기지 않는다.
func TestAuditQueueOverflowDropsOldestAndReportsGap(t *testing.T) {
	q := NewAuditQueue(3, 10)
	for i := uint64(1); i <= 5; i++ {
		q.Append(ev(100 + i)) // seq i, wall 100+i
	}

	b, _ := q.Next(context.Background(), 0)
	if !equal(seqs(b), []uint64{3, 4, 5}) {
		t.Fatalf("kept %v, want [3 4 5]", seqs(b))
	}
	if len(b.GetGaps()) != 1 {
		t.Fatalf("gaps = %v, want one", b.GetGaps())
	}
	g := b.GetGaps()[0]
	if g.GetCause() != pb.GapReport_CAUSE_LOCAL_STORE_FULL || !g.GetDroppedCountKnown() || g.GetDroppedCount() != 2 ||
		g.GetFromUnixNs() != 101 || g.GetToUnixNs() != 102 {
		t.Fatalf("gap = %v", g)
	}

	// 유실 보고도 ack 되면 지운다
	q.Ack(q.SeqEpoch(), 3)
	q.Append(ev(106))
	b, _ = q.Next(context.Background(), 3)
	if len(b.GetGaps()) != 0 {
		t.Fatalf("gap sent again after its batch was acked: %v", b.GetGaps())
	}
}
