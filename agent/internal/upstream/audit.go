package upstream

import (
	"context"
	"log"
	"sync/atomic"
	"time"

	"github.com/session-warrant/session-warrant/agent/internal/pb"
)

// AuditSource holds events until the server acks them. store.AuditQueue implements it.
type AuditSource interface {
	SeqEpoch() uint64
	// Next blocks until there are events with node_seq > after.
	Next(ctx context.Context, after uint64) (*pb.AuditBatch, error)
	// Ack drops everything through nodeSeq; called only after the server committed it.
	Ack(seqEpoch, nodeSeq uint64) error
}

// StreamAudit keeps one audit stream open, reconnecting with backoff, until ctx ends.
// Every new stream starts again from the oldest unacked event; the server is idempotent.
func (c *Client) StreamAudit(ctx context.Context, hello *pb.NodeHello, src AuditSource) error {
	backoff := c.minBackoff
	for {
		started := time.Now()
		acked, err := c.streamOnce(ctx, hello, src)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// A stream that was acked, or simply stayed up, was healthy: an idle node gets no acks.
		if acked || time.Since(started) >= c.maxBackoff {
			backoff = c.minBackoff
		}
		log.Printf("upstream: audit stream ended: %v (retry in %s)", err, backoff)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, c.maxBackoff)
	}
}

// One stream: send from the queue in one goroutine, apply acks in another.
// Returns when either side fails; the receive error carries the server's status.
func (c *Client) streamOnce(ctx context.Context, hello *pb.NodeHello, src AuditSource) (acked bool, err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	st, err := c.audit.Stream(ctx)
	if err != nil {
		return false, err
	}

	var gotAck atomic.Bool
	recvErr := make(chan error, 1)
	go func() {
		defer cancel() // unblocks src.Next below
		for {
			ack, err := st.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			// An ack of another epoch would delete events the server never saw.
			if ack.GetSeqEpoch() != src.SeqEpoch() {
				continue
			}
			if err := src.Ack(ack.GetSeqEpoch(), ack.GetAckedThroughNodeSeq()); err != nil {
				recvErr <- err
				return
			}
			gotAck.Store(true)
		}
	}()

	var after uint64
	for first := true; ; first = false {
		b, err := src.Next(ctx, after)
		if err != nil {
			break
		}
		if first {
			b.Node = hello // the server ties the stream to a node by this
		}
		if err := st.Send(b); err != nil {
			break // the real reason comes back from Recv
		}
		after = b.GetLastNodeSeq()
	}
	cancel()
	return gotAck.Load(), <-recvErr
}
