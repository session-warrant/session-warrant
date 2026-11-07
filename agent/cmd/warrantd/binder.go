package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/session-warrant/session-warrant/agent/internal/pamsock"
	"github.com/session-warrant/session-warrant/agent/internal/pb"
)

// auditSink is store.AuditQueue; nil when warrantd runs without upstream.
type auditSink interface {
	Append(e *pb.AuditEvent) uint64
}

// warrantSource is *registry.
type warrantSource interface {
	match(account, fp string, now time.Time) (*pb.Warrant, pb.UnwarrantedSessionEvent_Reason)
}

// cgroupTagger is *bpfmap.Maps.
type cgroupTagger interface {
	TagCgroup(cgroupID, warrantID uint64) error
	UntagCgroup(cgroupID uint64) error
}

type binder struct {
	maps     cgroupTagger
	audit    auditSink
	warrants warrantSource    // nil = no warrants
	now      func() time.Time // nil = time.Now
}

var _ pamsock.Binder = (*binder)(nil)

func (b *binder) Bind(ctx context.Context, r pamsock.Request) (uint64, error) {

	fp, err := pamsock.Fingerprint(r.AuthInfo)

	if err != nil {
		log.Printf("binder: fingerprint cgroup %d account %q: %v", r.CgroupID, r.LoginAccount, err)
		fp = ""
	}
	now := time.Now
	if b.now != nil {
		now = b.now
	}

	ws := b.warrants
	if ws == nil {
		ws = warrantList(nil)
	}
	w, reason := ws.match(r.LoginAccount, fp, now())
	if w != nil {
		id := w.GetWarrantId()
		if r.CgroupID == 0 {
			log.Printf("binder: warrant %d matched but session %q has no cgroup id", id, r.SessionID)
			b.unwarranted(r, fp, pb.UnwarrantedSessionEvent_REASON_NO_WARRANT, now())
			return 0, nil
		}
		if err := b.maps.TagCgroup(r.CgroupID, id); err != nil {
			b.unwarranted(r, fp, pb.UnwarrantedSessionEvent_REASON_NO_WARRANT, now())
			return 0, fmt.Errorf("tag cgroup %d with warrant %d: %w", r.CgroupID, id, err)
		}
		log.Printf("binder: warranted session warrant=%d cgroup=%d session=%q account=%q rhost=%q key=%q",
			id, r.CgroupID, r.SessionID, r.LoginAccount, r.RHost, fp)
		return id, nil
	}

	b.unwarranted(r, fp, reason, now())
	return 0, nil
}

// Called by Bind. The session runs untagged; log it and queue it for upstream.
func (b *binder) unwarranted(r pamsock.Request, fp string, reason pb.UnwarrantedSessionEvent_Reason, now time.Time) {
	log.Printf("binder: unwarranted session reason=%s cgroup=%d session=%q account=%q rhost=%q key=%q",
		strings.TrimPrefix(reason.String(), "REASON_"), r.CgroupID, r.SessionID, r.LoginAccount, r.RHost, fp)

	if b.audit != nil {
		b.audit.Append(unwarrantedEvent(r, fp, reason, now))
	}
}

// Called by Bind. Audit mode lets the login through, so the verdict is ALLOW with no warrant.
func unwarrantedEvent(r pamsock.Request, fp string, reason pb.UnwarrantedSessionEvent_Reason, now time.Time) *pb.AuditEvent {
	return &pb.AuditEvent{
		Hook:         pb.Hook_HOOK_AGENT,
		Verdict:      pb.Verdict_VERDICT_ALLOW,
		WallTsUnixNs: uint64(now.UnixNano()),
		TagSource:    pb.TagSource_TAG_NONE,
		Origin:       pb.Origin_ORIGIN_AGENT,
		Payload: &pb.AuditEvent_UnwarrantedSession{UnwarrantedSession: &pb.UnwarrantedSessionEvent{
			LoginAccount:      r.LoginAccount,
			SourceAddress:     r.RHost,
			CgroupId:          r.CgroupID,
			SessionId:         r.SessionID,
			Reason:            reason,
			SshKeyFingerprint: fp,
		}},
	}
}

func (b *binder) Unbind(ctx context.Context, cgroupID uint64) error {
	return b.maps.UntagCgroup(cgroupID)
}
