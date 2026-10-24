package store

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"sort"
	"sync"

	"google.golang.org/protobuf/proto"

	"github.com/session-warrant/session-warrant/agent/internal/pb"
)

// AuditQueue 는 서버가 ack 할 때까지 감사 이벤트를 메모리에 들고 있는다.
// bbolt 쪽 Store 가 생기기 전의 대역이다. 재시작하면 ack 안 된 기록을 잃으므로
// 프로세스마다 새 seq_epoch 를 뽑는다 — 잃은 구간은 나중에 AGENT_DOWN 으로 남긴다.
//
// 부르는 쪽: cmd/warrantd binder(Append), upstream.StreamAudit(Next · Ack).
type AuditQueue struct {
	mu        sync.Mutex
	epoch     uint64
	nextSeq   uint64
	events    []*pb.AuditEvent // ascending node_seq, none acked yet
	gaps      []queuedGap
	changed   chan struct{} // closed and replaced on every Append
	maxEvents int
	maxBatch  int
}

// A gap rides in the batch that carries beforeSeq, so it is acked with that batch.
type queuedGap struct {
	beforeSeq uint64
	gap       *pb.GapReport // replaced, never mutated: Next hands out clones
}

func NewAuditQueue(maxEvents, maxBatch int) *AuditQueue {
	return &AuditQueue{
		epoch:     randomEpoch(),
		nextSeq:   1,
		changed:   make(chan struct{}),
		maxEvents: maxEvents,
		maxBatch:  maxBatch,
	}
}

// 0 means "not set" on the wire and the server rejects it.
func randomEpoch() uint64 {
	var b [8]byte
	for {
		rand.Read(b[:])
		if e := binary.LittleEndian.Uint64(b[:]); e != 0 {
			return e
		}
	}
}

func (q *AuditQueue) SeqEpoch() uint64 {
	return q.epoch
}

// Append numbers e (node_seq from 1) and keeps it until acked. The caller must not touch e afterwards.
func (q *AuditQueue) Append(e *pb.AuditEvent) uint64 {
	q.mu.Lock()
	defer q.mu.Unlock()

	e.NodeSeq = q.nextSeq
	q.nextSeq++
	q.events = append(q.events, e)
	if len(q.events) > q.maxEvents {
		q.dropOldest()
	}

	close(q.changed)
	q.changed = make(chan struct{})
	return e.NodeSeq
}

// Drops events[0] and widens the trailing LOCAL_STORE_FULL gap if the drop is contiguous with it.
func (q *AuditQueue) dropOldest() {
	lost := q.events[0]
	q.events = q.events[1:]
	head := q.events[0].NodeSeq

	if n := len(q.gaps); n > 0 && q.gaps[n-1].beforeSeq == lost.NodeSeq {
		g := proto.Clone(q.gaps[n-1].gap).(*pb.GapReport)
		g.ToUnixNs = lost.WallTsUnixNs
		g.DroppedCount++
		q.gaps[n-1] = queuedGap{beforeSeq: head, gap: g}
		return
	}
	q.gaps = append(q.gaps, queuedGap{beforeSeq: head, gap: &pb.GapReport{
		FromUnixNs:        lost.WallTsUnixNs,
		ToUnixNs:          lost.WallTsUnixNs,
		DroppedCount:      1,
		DroppedCountKnown: true,
		Cause:             pb.GapReport_CAUSE_LOCAL_STORE_FULL,
	}})
}

// Next blocks until there are events with node_seq > after and returns up to maxBatch of them.
func (q *AuditQueue) Next(ctx context.Context, after uint64) (*pb.AuditBatch, error) {
	for {
		q.mu.Lock()
		i := sort.Search(len(q.events), func(i int) bool { return q.events[i].NodeSeq > after })
		if i < len(q.events) {
			b := q.batch(i, after)
			q.mu.Unlock()
			return b, nil
		}
		changed := q.changed
		q.mu.Unlock()

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-changed:
		}
	}
}

// Called by Next with q.mu held.
func (q *AuditQueue) batch(from int, after uint64) *pb.AuditBatch {
	to := min(from+q.maxBatch, len(q.events))
	b := &pb.AuditBatch{
		SeqEpoch:    q.epoch,
		LastNodeSeq: q.events[to-1].NodeSeq,
		Events:      append([]*pb.AuditEvent(nil), q.events[from:to]...),
	}
	for _, g := range q.gaps {
		if g.beforeSeq > after && g.beforeSeq <= b.LastNodeSeq {
			b.Gaps = append(b.Gaps, proto.Clone(g.gap).(*pb.GapReport))
		}
	}
	return b
}

// Ack drops everything through nodeSeq. An ack of another epoch is ignored.
func (q *AuditQueue) Ack(seqEpoch, nodeSeq uint64) error {
	if seqEpoch != q.epoch {
		return nil
	}
	q.mu.Lock()
	defer q.mu.Unlock()

	i := sort.Search(len(q.events), func(i int) bool { return q.events[i].NodeSeq > nodeSeq })
	q.events = q.events[i:]

	kept := q.gaps[:0]
	for _, g := range q.gaps {
		if g.beforeSeq > nodeSeq {
			kept = append(kept, g)
		}
	}
	q.gaps = kept
	return nil
}
