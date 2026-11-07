package main

import (
	"fmt"
	"log"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/session-warrant/session-warrant/agent/internal/bpfmap"
	"github.com/session-warrant/session-warrant/agent/internal/pb"
	"github.com/session-warrant/session-warrant/agent/internal/policy"
	"github.com/session-warrant/session-warrant/agent/internal/upstream"
)

// kernelWarrants is *bpfmap.Maps.
type kernelWarrants interface {
	PutWarrant(id uint64, w bpfmap.Warrant) error
	Revoke(id uint64) error
	SetActive(on bool) error
}

type source uint8

const (
	fromFile source = iota + 1
	fromCentral
)

type entry struct {
	w   *pb.Warrant
	src source
}

// registry holds the installed warrants: the local file at startup, central pushes after.
// upstream.Subscribe writes it while binder.Bind reads it, so every access takes mu.
type registry struct {
	host          string
	maps          kernelWarrants
	installPolicy func(id uint32, p *pb.Policy) error // policyInstaller.install
	keys          upstream.TrustKeys
	now           func() time.Time
	bootNs        func() (uint64, error)

	mu       sync.RWMutex
	byID     map[uint64]entry
	policies map[uint32]*pb.Policy // installed rules; a policy_id never changes content
	active   bool
}

var _ upstream.Applier = (*registry)(nil)

func newRegistry(host string, m kernelWarrants, installPolicy func(uint32, *pb.Policy) error, keys upstream.TrustKeys) *registry {
	return &registry{
		host: host, maps: m, installPolicy: installPolicy, keys: keys,
		now: time.Now, bootNs: bpfmap.BootNs,
		byID: map[uint64]entry{}, policies: map[uint32]*pb.Policy{},
	}
}

// Called by upstream.Subscribe for each pushed warrant.
func (r *registry) Apply(env *pb.SignedWarrant) (uint64, error) {
	w, err := upstream.Verify(env, r.keys)
	if err != nil {
		return 0, err
	}
	return w.GetWarrantId(), r.install(w, fromCentral)
}

// Called by Apply and loadLocalWarrants. Rules go in before the warrant, so a tagged
// session never sees a warrant without its rules; active_flag goes on with the first warrant.
func (r *registry) install(w *pb.Warrant, src source) error {
	if err := checkWarrant(w, r.host); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	id, pid := w.GetWarrantId(), w.GetPolicyId()
	if old, ok := r.byID[id]; ok && w.GetRevision() <= old.w.GetRevision() {
		return fmt.Errorf("revision %d is not newer than installed %d", w.GetRevision(), old.w.GetRevision())
	}
	if p, ok := r.policies[pid]; !ok {
		if err := r.installPolicy(pid, w.GetPolicy()); err != nil {
			return fmt.Errorf("policy %d: %w", pid, err)
		}
		r.policies[pid] = w.GetPolicy()
	} else if !proto.Equal(p, w.GetPolicy()) {
		return fmt.Errorf("policy %d arrived with different rules: a policy_id is never reused", pid)
	}

	boot, err := r.bootNs()
	if err != nil {
		return err
	}
	if err := r.maps.PutWarrant(id, kernelWarrant(w, r.now(), boot)); err != nil {
		return err
	}
	r.byID[id] = entry{w: w, src: src}
	if !r.active {
		if err := r.maps.SetActive(true); err != nil {
			log.Printf("warrants: %v", err)
		} else {
			r.active = true
		}
	}
	log.Printf("warrants: installed %d rev=%d account=%q policy=%d mode=%s revoked=%t expires=%s",
		id, w.GetRevision(), w.GetLoginAccount(), pid, w.GetMode(), w.GetRevoked(),
		time.Unix(0, int64(w.GetExpiresAtUnixNs())).Format(time.RFC3339))
	return nil
}

// Called by upstream.Subscribe on ResyncComplete. Central warrants the server no longer lists are
// revoked, not deleted: a deleted entry would leave its tagged sessions unmanaged instead of cut off.
// active_flag stays on for the same reason.
func (r *registry) Resync(active map[uint64]struct{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, e := range r.byID {
		if _, ok := active[id]; ok || e.src != fromCentral {
			continue
		}
		if err := r.maps.Revoke(id); err != nil {
			log.Printf("warrants: resync: revoke %d: %v", id, err)
			continue
		}
		delete(r.byID, id)
		log.Printf("warrants: resync: revoked %d, no longer active on the server", id)
	}
}

// Called by upstream.Subscribe; central warrants only.
func (r *registry) Revisions() map[uint64]uint32 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := map[uint64]uint32{}
	for id, e := range r.byID {
		if e.src == fromCentral {
			out[id] = e.w.GetRevision()
		}
	}
	return out
}

// Called by binder.Bind.
func (r *registry) match(account, fp string, now time.Time) (*pb.Warrant, pb.UnwarrantedSessionEvent_Reason) {
	r.mu.RLock()
	ws := make([]*pb.Warrant, 0, len(r.byID))
	for _, e := range r.byID {
		ws = append(ws, e.w)
	}
	r.mu.RUnlock()
	return matchWarrant(ws, account, fp, now)
}

func (r *registry) len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byID)
}

// policyInstaller compiles a policy into the rule maps and watches its files, recompiling
// when one is replaced (S4). The watcher calls back on its own goroutine, so specs takes mu.
type policyInstaller struct {
	maps    *bpfmap.Maps
	watcher *policy.Watcher // nil: rules do not follow replaced files

	mu    sync.Mutex
	specs map[uint32]policy.Spec
}

func newPolicyInstaller(m *bpfmap.Maps) *policyInstaller {
	p := &policyInstaller{maps: m, specs: map[uint32]policy.Spec{}}
	w, err := policy.NewWatcher()
	if err != nil {
		log.Printf("warrants: watcher: %v (rules will not follow replaced files)", err)
		return p
	}
	_ = w.OnChange(p.recompile)
	p.watcher = w
	return p
}

// Called by registry.install, once per policy_id.
func (p *policyInstaller) install(id uint32, pp *pb.Policy) error {
	s, err := policySpec(pp)
	if err != nil {
		return err
	}
	c, err := policy.Compile(id, s)
	if err != nil {
		return err
	}
	for _, msg := range c.Warnings {
		log.Printf("warrants: policy %d: %s", id, msg)
	}
	if err := c.Apply(p.maps); err != nil {
		return err
	}
	p.mu.Lock()
	p.specs[id] = s
	p.mu.Unlock()
	if p.watcher != nil {
		_ = p.watcher.Watch(c)
	}
	return nil
}

// Called by the watcher when a rule's file is replaced, or its rules silently stop matching.
func (p *policyInstaller) recompile(id uint32) {
	p.mu.Lock()
	s := p.specs[id]
	p.mu.Unlock()
	c, err := policy.Compile(id, s)
	if err == nil {
		err = c.Apply(p.maps)
	}
	if err != nil {
		log.Printf("warrants: policy %d changed on disk, recompile: %v", id, err)
		return
	}
	log.Printf("warrants: policy %d changed on disk, recompiled", id)
	_ = p.watcher.Watch(c)
}

func (p *policyInstaller) Close() error {
	if p.watcher == nil {
		return nil
	}
	return p.watcher.Close()
}
