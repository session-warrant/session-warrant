package upstream

import (
	"context"
	"log"
	"time"

	"github.com/session-warrant/session-warrant/agent/internal/pb"
)

// Heartbeat tells the server the node is alive and returns how many active warrants the server expects it to
// hold. A count different from the node's own means a push was missed; the caller resubscribes.
func (c *Client) Heartbeat(ctx context.Context, hello *pb.NodeHello, activeWarrants uint32, ringbufDroppedTotal uint64) (expected uint32, err error) {
	resp, err := c.push.Heartbeat(ctx, &pb.HeartbeatRequest{
		Node:                hello,
		ActiveWarrants:      activeWarrants,
		RingbufDroppedTotal: ringbufDroppedTotal,
	})
	if err != nil {
		return 0, err
	}
	return resp.GetExpectedActiveWarrants(), nil
}

// NodeState is what HeartbeatLoop reports each time: the warrants in the kernel map and the ringbuf drops since
// boot. cmd/warrantd supplies it.
type NodeState func() (activeWarrants uint32, ringbufDroppedTotal uint64)

// HeartbeatLoop sends a heartbeat every interval until ctx ends. When the server expects a different number of
// active warrants, mismatch is called (warrantd resubscribes there). A failed heartbeat is logged and the loop
// goes on — the kernel keeps enforcing without the server (§17).
func (c *Client) HeartbeatLoop(ctx context.Context, interval time.Duration, hello *pb.NodeHello, state NodeState,
	mismatch func(expected, have uint32)) error {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		have, dropped := state()
		hctx, cancel := context.WithTimeout(ctx, interval)
		expected, err := c.Heartbeat(hctx, hello, have, dropped)
		cancel()
		switch {
		case ctx.Err() != nil:
			return ctx.Err()
		case err != nil:
			log.Printf("upstream: heartbeat: %v", err)
		case expected != have && mismatch != nil:
			mismatch(expected, have)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}

// LookupActiveWarrant asks the server for the warrant matching hostname, login account and key fingerprint, for
// when the local cache is empty. The server answers only an exact match on all three, and at most one.
// The caller bounds ctx and treats an error or timeout as "no warrant": fail-open, the session is recorded as
// unwarranted rather than refused. The envelopes are unverified — run Verify before using them.
func (c *Client) LookupActiveWarrant(ctx context.Context, hostname, loginAccount, fingerprint string) ([]*pb.SignedWarrant, error) {
	resp, err := c.push.LookupActiveWarrant(ctx, &pb.LookupRequest{
		Hostname:          hostname,
		LoginAccount:      loginAccount,
		SshKeyFingerprint: fingerprint,
	})
	if err != nil {
		return nil, err
	}
	return resp.GetWarrants(), nil
}
