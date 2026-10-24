package main

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/session-warrant/session-warrant/agent/internal/bpfmap"
	"github.com/session-warrant/session-warrant/agent/internal/pamsock"
	"github.com/session-warrant/session-warrant/agent/internal/pb"
)

// auditSink is store.AuditQueue; nil when warrantd runs without upstream.
type auditSink interface {
	Append(e *pb.AuditEvent) uint64
}

type binder struct {
	maps  *bpfmap.Maps
	audit auditSink
}

var _ pamsock.Binder = (*binder)(nil)

func (b *binder) Bind(ctx context.Context, r pamsock.Request) (uint64, error) {

	fp, err := pamsock.Fingerprint(r.AuthInfo)

	if err != nil {
		log.Printf("binder: fingerprint cgroup %d account %q: %v", r.CgroupID, r.LoginAccount, err)
		fp = ""
	}
	reason := pb.UnwarrantedSessionEvent_REASON_NO_WARRANT
	if fp == "" {
		reason = pb.UnwarrantedSessionEvent_REASON_NO_KEY
	}
	log.Printf("binder: unwarranted session reason=%s cgroup=%d session=%q account=%q rhost=%q key=%q",
		strings.TrimPrefix(reason.String(), "REASON_"), r.CgroupID, r.SessionID, r.LoginAccount, r.RHost, fp)

	if b.audit != nil {
		b.audit.Append(unwarrantedEvent(r, fp, reason, time.Now()))
	}
	return 0, nil
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
