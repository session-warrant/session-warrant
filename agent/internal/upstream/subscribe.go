package upstream

import (
	"context"
	"log"
	"time"

	"github.com/session-warrant/session-warrant/agent/internal/pb"
)

// Applier is the node side of Subscribe; cmd/warrantd's registry implements it.
type Applier interface {
	// Apply verifies and installs one pushed warrant. It returns the warrant id once the
	// signature checked out, even if installing failed, so a resync does not revoke it.
	Apply(env *pb.SignedWarrant) (warrantID uint64, err error)
	// Resync gets every id this stream delivered before ResyncComplete: the server's active set.
	// Not called when fewer verified than the server listed; an incomplete set would revoke valid warrants.
	Resync(active map[uint64]struct{})
	// Revisions is what the node holds now; sent for diagnosis only.
	Revisions() map[uint64]uint32
}

// Subscribe keeps one push stream open, reconnecting with backoff, until ctx ends.
// Each stream starts with the full active set, then ResyncComplete, then changes.
func (c *Client) Subscribe(ctx context.Context, hello *pb.NodeHello, a Applier) error {
	backoff := c.minBackoff
	for {
		started := time.Now()
		resynced, err := c.subscribeOnce(ctx, hello, a)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if resynced || time.Since(started) >= c.maxBackoff {
			backoff = c.minBackoff
		}
		log.Printf("upstream: warrant stream ended: %v (retry in %s)", err, backoff)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, c.maxBackoff)
	}
}

func (c *Client) subscribeOnce(ctx context.Context, hello *pb.NodeHello, a Applier) (resynced bool, err error) {
	st, err := c.push.Subscribe(ctx, &pb.SubscribeRequest{Node: hello, CachedRevisions: a.Revisions()})
	if err != nil {
		return false, err
	}
	seen := map[uint64]struct{}{}
	for {
		m, err := st.Recv()
		if err != nil {
			return resynced, err
		}
		switch b := m.GetBody().(type) {
		case *pb.PushMessage_Warrant:
			id, err := a.Apply(b.Warrant)
			if err != nil {
				log.Printf("upstream: push rejected (warrant %d): %v", id, err)
			}
			if id != 0 && !resynced {
				seen[id] = struct{}{}
			}
		case *pb.PushMessage_ResyncComplete:
			if resynced {
				continue // one active set per stream
			}
			resynced = true
			n := b.ResyncComplete.GetActiveCount()
			// Fewer verified than the server listed means pushes we could not check, e.g. a stale
			// trust key. Revoking on that set would cut valid warrants; keep them and say so (§17).
			if uint32(len(seen)) < n {
				log.Printf("upstream: RESYNC SKIPPED: server listed %d active, only %d verified; nothing revoked (check -trust-keys)",
					n, len(seen))
				continue
			}
			log.Printf("upstream: resync complete: server %d active, %d verified", n, len(seen))
			a.Resync(seen)
		}
	}
}
