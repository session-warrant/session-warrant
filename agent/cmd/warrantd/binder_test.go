package main

import (
	"context"
	"testing"
	"time"

	"github.com/session-warrant/session-warrant/agent/internal/pamsock"
	"github.com/session-warrant/session-warrant/agent/internal/pb"
)

type sink struct{ got []*pb.AuditEvent }

func (s *sink) Append(e *pb.AuditEvent) uint64 {
	s.got = append(s.got, e)
	return uint64(len(s.got))
}

func open(authInfo string) pamsock.Request {
	return pamsock.Request{Op: "OPEN", SessionID: "c1", CgroupID: 7594,
		LoginAccount: "ec2-user", RHost: "10.0.0.5", AuthInfo: authInfo}
}

// 서버의 AuditProtoMapper 가 받아 주는 모양이어야 한다 — 시각 · 출처 · 사유가 비면 거부된다.
func TestUnwarrantedEventHasWhatTheServerRequires(t *testing.T) {
	now := time.Unix(1_790_000_000, 123)
	e := unwarrantedEvent(open(""), "SHA256:abc", pb.UnwarrantedSessionEvent_REASON_NO_WARRANT, now)

	if e.GetWallTsUnixNs() != uint64(now.UnixNano()) {
		t.Errorf("wall_ts = %d, want %d", e.GetWallTsUnixNs(), now.UnixNano())
	}
	if e.GetHook() != pb.Hook_HOOK_AGENT || e.GetOrigin() != pb.Origin_ORIGIN_AGENT || e.GetTagSource() != pb.TagSource_TAG_NONE {
		t.Errorf("hook %v origin %v tag %v", e.GetHook(), e.GetOrigin(), e.GetTagSource())
	}
	if e.GetVerdict() != pb.Verdict_VERDICT_ALLOW || e.GetWarrantId() != 0 {
		t.Errorf("verdict %v warrant %d: audit mode lets the login through", e.GetVerdict(), e.GetWarrantId())
	}
	u := e.GetUnwarrantedSession()
	if u.GetLoginAccount() != "ec2-user" || u.GetSourceAddress() != "10.0.0.5" || u.GetCgroupId() != 7594 ||
		u.GetSessionId() != "c1" || u.GetSshKeyFingerprint() != "SHA256:abc" ||
		u.GetReason() != pb.UnwarrantedSessionEvent_REASON_NO_WARRANT {
		t.Errorf("unwarranted session = %v", u)
	}
}

// 키 없이(비밀번호 등) 들어오면 NO_KEY 로 큐에 들어간다.
func TestBindQueuesUnwarrantedSession(t *testing.T) {
	s := &sink{}
	b := &binder{audit: s}

	if _, err := b.Bind(context.Background(), open("password")); err != nil {
		t.Fatal(err)
	}
	if len(s.got) != 1 {
		t.Fatalf("queued %d events, want 1", len(s.got))
	}
	if r := s.got[0].GetUnwarrantedSession().GetReason(); r != pb.UnwarrantedSessionEvent_REASON_NO_KEY {
		t.Fatalf("reason = %v, want NO_KEY", r)
	}
}

// 중앙 없이 돌 때는 로그만 남는다.
func TestBindWithoutUpstreamOnlyLogs(t *testing.T) {
	b := &binder{}
	if _, err := b.Bind(context.Background(), open("")); err != nil {
		t.Fatal(err)
	}
}
