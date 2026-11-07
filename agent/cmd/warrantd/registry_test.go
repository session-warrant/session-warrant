package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/session-warrant/session-warrant/agent/internal/bpfmap"
	"github.com/session-warrant/session-warrant/agent/internal/pb"
	"github.com/session-warrant/session-warrant/agent/internal/upstream"
)

// fakeKernel stands in for *bpfmap.Maps.
type fakeKernel struct {
	puts    map[uint64]bpfmap.Warrant
	revoked []uint64
	active  []bool
}

func (k *fakeKernel) PutWarrant(id uint64, w bpfmap.Warrant) error {
	if k.puts == nil {
		k.puts = map[uint64]bpfmap.Warrant{}
	}
	k.puts[id] = w
	return nil
}

func (k *fakeKernel) Revoke(id uint64) error {
	k.revoked = append(k.revoked, id)
	return nil
}

func (k *fakeKernel) SetActive(on bool) error {
	k.active = append(k.active, on)
	return nil
}

type testRegistry struct {
	*registry
	kernel   *fakeKernel
	policies []uint32
	priv     ed25519.PrivateKey
}

func newTestRegistry(t *testing.T) *testRegistry {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tr := &testRegistry{kernel: &fakeKernel{}, priv: priv}
	tr.registry = newRegistry("node-1", tr.kernel, func(id uint32, _ *pb.Policy) error {
		tr.policies = append(tr.policies, id)
		return nil
	}, upstream.TrustKeys{"k1": pub})
	tr.now = func() time.Time { return now }
	tr.bootNs = func() (uint64, error) { return 1_000, nil }
	return tr
}

func (tr *testRegistry) signed(t *testing.T, w *pb.Warrant) *pb.SignedWarrant {
	t.Helper()
	b, err := proto.Marshal(w)
	if err != nil {
		t.Fatal(err)
	}
	return &pb.SignedWarrant{Warrant: b, Signature: ed25519.Sign(tr.priv, b), KeyId: "k1"}
}

func (tr *testRegistry) push(t *testing.T, w *pb.Warrant) error {
	t.Helper()
	_, err := tr.Apply(tr.signed(t, w))
	return err
}

func revision(w *pb.Warrant, rev uint32) *pb.Warrant {
	w.Revision = rev
	return w
}

// 중앙에서 받은 영장은 규칙 → 영장 → active_flag 순으로 커널에 들어가고, 그 뒤 세션이 찾을 수 있다.
func TestRegistryInstallsPushedWarrant(t *testing.T) {
	tr := newTestRegistry(t)
	if err := tr.push(t, revision(warrant(9), 1)); err != nil {
		t.Fatal(err)
	}
	if len(tr.policies) != 1 || tr.policies[0] != 7 {
		t.Fatalf("policies installed %v, want [7]", tr.policies)
	}
	if _, ok := tr.kernel.puts[9]; !ok {
		t.Fatalf("kernel warrants %v, want 9", tr.kernel.puts)
	}
	if len(tr.kernel.active) != 1 || !tr.kernel.active[0] {
		t.Fatalf("active_flag writes %v, want [true]", tr.kernel.active)
	}
	if w, _ := tr.match("ec2-user", aliceFP, now); w.GetWarrantId() != 9 {
		t.Fatalf("match = %v, want warrant 9", w)
	}
}

// 서명이 틀린 영장은 커널에 한 바이트도 쓰지 않는다.
func TestRegistryRejectsUnsignedPush(t *testing.T) {
	tr := newTestRegistry(t)
	env := tr.signed(t, warrant(9))
	env.Signature[0] ^= 1

	id, err := tr.Apply(env)
	if err == nil || id != 0 {
		t.Fatalf("id %d err %v, want 0 and an error", id, err)
	}
	if len(tr.kernel.puts) != 0 || len(tr.policies) != 0 || len(tr.kernel.active) != 0 {
		t.Fatalf("wrote to the kernel: %v %v %v", tr.kernel.puts, tr.policies, tr.kernel.active)
	}
}

// 같은 영장은 revision 이 올라갈 때만 바뀐다. 늦게 도착한 옛 revision 이 연장 · 취소를 되돌리면 안 된다.
func TestRegistryAppliesOnlyNewerRevision(t *testing.T) {
	tr := newTestRegistry(t)
	if err := tr.push(t, revision(warrant(9), 2)); err != nil {
		t.Fatal(err)
	}
	if err := tr.push(t, revision(warrant(9), 2)); err == nil {
		t.Fatal("accepted the same revision twice")
	}
	if err := tr.push(t, revision(warrant(9), 1)); err == nil {
		t.Fatal("accepted an older revision")
	}
}

// 취소는 새 revision 으로 온다. 커널 값의 revoked 가 서고, 새 세션은 그 영장을 못 받는다.
func TestRegistryRevocationReachesKernelAndBinder(t *testing.T) {
	tr := newTestRegistry(t)
	tr.push(t, revision(warrant(9), 1))
	w := revision(warrant(9), 2)
	w.Revoked = true
	if err := tr.push(t, w); err != nil {
		t.Fatal(err)
	}
	if tr.kernel.puts[9].Revoked != 1 {
		t.Fatalf("kernel warrant %+v, want revoked", tr.kernel.puts[9])
	}
	if got, reason := tr.match("ec2-user", aliceFP, now); got != nil || reason != pb.UnwarrantedSessionEvent_REASON_NO_WARRANT {
		t.Fatalf("match = %v %v, want none", got, reason)
	}
}

// policy_id 는 불변이다. 같은 id 에 다른 규칙이 오면 이미 붙은 영장들의 규칙이 몰래 바뀌는 것이다.
func TestRegistryRejectsChangedPolicyUnderSameID(t *testing.T) {
	tr := newTestRegistry(t)
	tr.push(t, revision(warrant(9), 1))

	w := revision(warrant(10), 1)
	w.Policy = &pb.Policy{Name: "p", ExecRules: []*pb.ExecRule{{Path: "/usr/bin/bash"}}}
	if err := tr.push(t, w); err == nil {
		t.Fatal("accepted different rules under policy 7")
	}
	if _, ok := tr.kernel.puts[10]; ok {
		t.Fatal("installed warrant 10")
	}
}

// 같은 정책을 쓰는 영장이 여럿이어도 규칙은 한 번만 컴파일한다.
func TestRegistryInstallsPolicyOncePerID(t *testing.T) {
	tr := newTestRegistry(t)
	tr.push(t, revision(warrant(9), 1))
	tr.push(t, revision(warrant(10), 1))
	if len(tr.policies) != 1 || len(tr.kernel.puts) != 2 {
		t.Fatalf("policies %v warrants %v", tr.policies, tr.kernel.puts)
	}
}

// 규칙을 못 넣으면 영장도 넣지 않는다. 규칙 없는 영장은 전부 거부로 판정된다.
func TestRegistrySkipsWarrantWhenPolicyFails(t *testing.T) {
	tr := newTestRegistry(t)
	tr.installPolicy = func(uint32, *pb.Policy) error { return errors.New("stat /opt/app: no such file") }

	id, err := tr.Apply(tr.signed(t, revision(warrant(9), 1)))
	if err == nil || id != 9 {
		t.Fatalf("id %d err %v, want 9 and an error", id, err)
	}
	if len(tr.kernel.puts) != 0 {
		t.Fatalf("installed %v without its rules", tr.kernel.puts)
	}
}

// 다른 노드 앞으로 발급된 영장은 서명이 맞아도 받지 않는다.
func TestRegistryRejectsOtherHost(t *testing.T) {
	tr := newTestRegistry(t)
	w := revision(warrant(9), 1)
	w.TargetHosts = []string{"node-2"}
	if err := tr.push(t, w); err == nil || len(tr.kernel.puts) != 0 {
		t.Fatalf("err %v puts %v", err, tr.kernel.puts)
	}
}

// 서버의 활성 집합에서 빠진 중앙 영장은 취소한다. 맵 값은 revoked 로 남겨, 이미 붙은 세션이 끊기게 한다.
// 로컬 파일 영장은 서버가 모르는 것이라 건드리지 않는다.
func TestRegistryResyncRevokesOnlyMissingCentralWarrants(t *testing.T) {
	tr := newTestRegistry(t)
	if err := tr.install(warrant(1), fromFile); err != nil {
		t.Fatal(err)
	}
	tr.push(t, revision(warrant(2), 1))
	tr.push(t, revision(warrant(3), 1))

	tr.Resync(map[uint64]struct{}{3: {}})

	if len(tr.kernel.revoked) != 1 || tr.kernel.revoked[0] != 2 {
		t.Fatalf("revoked %v, want [2]", tr.kernel.revoked)
	}
	if got := tr.Revisions(); len(got) != 1 || got[3] != 1 {
		t.Fatalf("revisions %v, want {3: 1}", got)
	}
	// active_flag 는 끄지 않는다. 끄면 revoked 로 남긴 영장까지 판정에서 빠진다.
	for _, on := range tr.kernel.active {
		if !on {
			t.Fatalf("active_flag writes %v", tr.kernel.active)
		}
	}
}
