package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"slices"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/session-warrant/session-warrant/agent/internal/bpfmap"
	"github.com/session-warrant/session-warrant/agent/internal/pb"
	"github.com/session-warrant/session-warrant/agent/internal/policy"
)

// Warrant conversion and matching, shared by both sources: the local file (-warrants, read once
// at startup) and central pushes (upstream.Subscribe). Both go through registry.install.

// Called by loadWarrants. Unknown fields are errors: a typo must not drop a rule silently.
func parseWarrantFile(b []byte) ([]*pb.Warrant, error) {
	var raw []json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("JSON array of Warrant: %w", err)
	}
	out := make([]*pb.Warrant, 0, len(raw))
	for i, r := range raw {
		w := &pb.Warrant{}
		if err := protojson.Unmarshal(r, w); err != nil {
			return nil, fmt.Errorf("warrant #%d: %w", i, err)
		}
		out = append(out, w)
	}
	return out, nil
}

// Called by registry.install for both sources. ENFORCE and break_glass stay closed this semester (audit mode only).
func checkWarrant(w *pb.Warrant, hostname string) error {
	switch {
	case w.GetWarrantId() == 0:
		return errors.New("warrant_id is 0")
	case w.GetPolicyId() == 0:
		return errors.New("policy_id is 0")
	case w.GetExpiresAtUnixNs() == 0:
		return errors.New("expires_at_unix_ns is 0: a warrant must expire")
	case !slices.Contains(w.GetTargetHosts(), hostname):
		return fmt.Errorf("target_hosts %v does not include %q", w.GetTargetHosts(), hostname)
	case w.GetMode() == pb.Mode_MODE_ENFORCE:
		return errors.New("mode MODE_ENFORCE is out of scope: use MODE_OBSERVE or MODE_DRYRUN")
	case w.GetBreakGlass():
		return errors.New("break_glass is out of scope")
	}
	return nil
}

// Converts absolute expiry to the boot clock the kernel compares against; the only place this happens.
func kernelWarrant(w *pb.Warrant, now time.Time, bootNs uint64) bpfmap.Warrant {
	exp := int64(bootNs) + (int64(w.GetExpiresAtUnixNs()) - now.UnixNano())
	if exp < 1 {
		exp = 1 // already expired; 0 would mean "never expires"
	}
	k := bpfmap.Warrant{
		ExpiresNs: uint64(exp),
		GraceNs:   w.GetGraceWindowNs(),
		SubjectID: w.GetSubjectId(),
		PolicyID:  w.GetPolicyId(),
		Mode:      uint8(w.GetMode()),
		OnExpiry:  uint8(w.GetOnExpiry()),
	}
	if w.GetRevoked() {
		k.Revoked = 1
	}
	return k
}

// Called by policyInstaller.install. Enum values match the policy and bpfmap constants by construction.
func policySpec(p *pb.Policy) (policy.Spec, error) {
	s := policy.Spec{Name: p.GetName(), ReadWatchPaths: p.GetReadWatchPaths(), InspectUDP: p.GetInspectUdp()}
	for _, r := range p.GetExecRules() {
		s.ExecRules = append(s.ExecRules, policy.ExecRule{Path: r.GetPath()})
	}
	for _, r := range p.GetWriteRules() {
		s.WriteRules = append(s.WriteRules, policy.WriteRule{
			Path: r.GetPath(), Recursive: r.GetRecursive(), Effect: policy.Effect(r.GetEffect())})
	}
	for _, r := range p.GetNetRules() {
		if r.GetPort() > 0xffff {
			return policy.Spec{}, fmt.Errorf("net rule %s: port %d", r.GetCidr(), r.GetPort())
		}
		s.NetRules = append(s.NetRules, policy.NetRule{
			CIDR: r.GetCidr(), Port: uint16(r.GetPort()), Proto: uint8(r.GetProto())})
	}
	return s, nil
}

// Called by run before attach. A missing file means no local warrants; bad entries are skipped, never fatal (§17).
func loadLocalWarrants(r *registry, path string) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	var ws []*pb.Warrant
	if err == nil {
		ws, err = parseWarrantFile(b)
	}
	if err != nil {
		log.Printf("warrants: %s: %v (running without local warrants)", path, err)
		return
	}
	for _, w := range ws {
		if err := r.install(w, fromFile); err != nil {
			log.Printf("warrants: skip %d: %v", w.GetWarrantId(), err)
		}
	}
}

// warrantList is a fixed set; binder uses it when it has no registry.
type warrantList []*pb.Warrant

func (l warrantList) match(account, fp string, now time.Time) (*pb.Warrant, pb.UnwarrantedSessionEvent_Reason) {
	return matchWarrant(l, account, fp, now)
}

// Called by binder.Bind. Picks the live warrant for this account and key; the latest expiry wins.
func matchWarrant(ws []*pb.Warrant, account, fp string, now time.Time) (*pb.Warrant, pb.UnwarrantedSessionEvent_Reason) {
	if fp == "" {
		return nil, pb.UnwarrantedSessionEvent_REASON_NO_KEY
	}
	var best *pb.Warrant
	accountHas := false
	for _, w := range ws {
		if w.GetRevoked() || w.GetExpiresAtUnixNs() <= uint64(now.UnixNano()) || w.GetLoginAccount() != account {
			continue
		}
		accountHas = true
		if !slices.Contains(w.GetSshKeyFingerprints(), fp) {
			continue
		}
		if best == nil || w.GetExpiresAtUnixNs() > best.GetExpiresAtUnixNs() {
			best = w
		}
	}
	switch {
	case best != nil:
		return best, pb.UnwarrantedSessionEvent_REASON_UNSPECIFIED
	case accountHas:
		return nil, pb.UnwarrantedSessionEvent_REASON_KEY_MISMATCH
	}
	return nil, pb.UnwarrantedSessionEvent_REASON_NO_WARRANT
}
