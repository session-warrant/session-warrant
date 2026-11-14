package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/session-warrant/session-warrant/agent/internal/bpfmap"
	"github.com/session-warrant/session-warrant/agent/internal/pamsock"
	"github.com/session-warrant/session-warrant/agent/internal/pb"
)

// Generated with ssh-keygen; same key as pamsock_test.
const (
	aliceKey = "publickey ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILMSAbXyR+rORY6QMtD5jNWmiMxwd7QXBOJJmuw20r7N\n"
	aliceFP  = "SHA256:jboFL1JPH9fffG2ASuLTLJfvaA7inV9SPlWM5gciBjs"
)

var now = time.Unix(1_790_000_000, 0)

func warrant(id uint64) *pb.Warrant {
	return &pb.Warrant{
		WarrantId:          id,
		SubjectId:          42,
		LoginAccount:       "ec2-user",
		SshKeyFingerprints: []string{aliceFP},
		TargetHosts:        []string{"node-1"},
		ExpiresAtUnixNs:    uint64(now.Add(time.Hour).UnixNano()),
		Mode:               pb.Mode_MODE_DRYRUN,
		PolicyId:           7,
		Policy:             &pb.Policy{Name: "p"},
	}
}

type tagger struct {
	tagged map[uint64]uint64
	err    error
}

func (t *tagger) TagCgroup(cg, wid uint64) error {
	if t.err != nil {
		return t.err
	}
	if t.tagged == nil {
		t.tagged = map[uint64]uint64{}
	}
	t.tagged[cg] = wid
	return nil
}

func (t *tagger) UntagCgroup(cg uint64) error {
	delete(t.tagged, cg)
	return nil
}

// 파일은 proto 의 Warrant 를 JSON 배열로 적는다. 필드 이름은 proto 그대로다.
func TestParseWarrantFileReadsProtoJSON(t *testing.T) {
	in := `[{
		"warrant_id": "11",
		"login_account": "ec2-user",
		"ssh_key_fingerprints": ["` + aliceFP + `"],
		"target_hosts": ["node-1"],
		"expires_at_unix_ns": "1790003600000000000",
		"mode": "MODE_DRYRUN",
		"policy_id": 7,
		"policy": {"exec_rules": [{"path": "/usr/bin/true"}],
		           "write_rules": [{"path": "/tmp", "recursive": true, "effect": "EFFECT_ALLOW"}]}
	}]`
	ws, err := parseWarrantFile([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(ws) != 1 {
		t.Fatalf("got %d warrants, want 1", len(ws))
	}
	w := ws[0]
	if w.GetWarrantId() != 11 || w.GetMode() != pb.Mode_MODE_DRYRUN || w.GetPolicyId() != 7 ||
		w.GetPolicy().GetWriteRules()[0].GetEffect() != pb.WriteRule_EFFECT_ALLOW {
		t.Errorf("warrant = %v", w)
	}
}

// deploy 의 예시 파일이 실제로 읽히고 검사를 통과해야 한다.
func TestExampleWarrantFileIsValid(t *testing.T) {
	b, err := os.ReadFile("../../../deploy/systemd/warrants.example.json")
	if err != nil {
		t.Fatal(err)
	}
	ws, err := parseWarrantFile(b)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range ws {
		if err := checkWarrant(w, "lima-sw"); err != nil {
			t.Errorf("warrant %d: %v", w.GetWarrantId(), err)
		}
	}
}

// 오타 난 필드가 조용히 빠지면 규칙 없는 영장이 붙는다.
func TestParseWarrantFileRejectsUnknownField(t *testing.T) {
	if _, err := parseWarrantFile([]byte(`[{"warrant_id": "1", "polcy_id": 7}]`)); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestCheckWarrant(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(w *pb.Warrant)
		want   string // substring of the error, "" = accepted
	}{
		{"정상", func(w *pb.Warrant) {}, ""},
		{"영장 id 없음", func(w *pb.Warrant) { w.WarrantId = 0 }, "warrant_id"},
		{"정책 id 없음", func(w *pb.Warrant) { w.PolicyId = 0 }, "policy_id"},
		{"만료 없음", func(w *pb.Warrant) { w.ExpiresAtUnixNs = 0 }, "expires_at"},
		{"다른 노드 영장", func(w *pb.Warrant) { w.TargetHosts = []string{"node-2"} }, "target_hosts"},
		{"강제 모드", func(w *pb.Warrant) { w.Mode = pb.Mode_MODE_ENFORCE }, "ENFORCE"},
		{"비상 영장", func(w *pb.Warrant) { w.BreakGlass = true }, "break_glass"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := warrant(1)
			tt.mutate(w)
			err := checkWarrant(w, "node-1")
			switch {
			case tt.want == "" && err != nil:
				t.Fatalf("rejected: %v", err)
			case tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)):
				t.Fatalf("err = %v, want mention of %q", err, tt.want)
			}
		})
	}
}

// 커널은 boot 기준 시계만 안다. 1시간 뒤 만료는 boot 시각 + 1시간이어야 한다.
func TestKernelWarrantConvertsExpiryToBootClock(t *testing.T) {
	const boot = uint64(50 * time.Second)
	w := warrant(1)
	w.GraceWindowNs = uint64(time.Minute)
	w.OnExpiry = pb.OnExpiry_ON_EXPIRY_KILL

	k := kernelWarrant(w, now, boot)
	want := bpfmap.Warrant{
		ExpiresNs: boot + uint64(time.Hour),
		GraceNs:   uint64(time.Minute),
		SubjectID: 42,
		PolicyID:  7,
		Mode:      bpfmap.ModeDryRun,
		OnExpiry:  bpfmap.OnExpiryKill,
	}
	if k != want {
		t.Fatalf("got %+v\nwant %+v", k, want)
	}
}

// 이미 만료된 영장은 0(만료 없음)이 되면 안 된다. boot 이전 시각도 마찬가지다.
func TestKernelWarrantKeepsPastExpiryExpired(t *testing.T) {
	w := warrant(1)
	w.ExpiresAtUnixNs = uint64(now.Add(-time.Hour).UnixNano())
	w.Revoked = true

	k := kernelWarrant(w, now, uint64(time.Second))
	if k.ExpiresNs == 0 || k.ExpiresNs > uint64(time.Second) {
		t.Fatalf("ExpiresNs = %d, want in (0, boot]", k.ExpiresNs)
	}
	if k.Revoked != 1 {
		t.Fatal("revoked lost")
	}
}

func TestMatchWarrant(t *testing.T) {
	expired := warrant(2)
	expired.ExpiresAtUnixNs = uint64(now.Add(-time.Minute).UnixNano())
	revoked := warrant(3)
	revoked.Revoked = true
	later := warrant(4)
	later.ExpiresAtUnixNs = uint64(now.Add(2 * time.Hour).UnixNano())
	otherKey := warrant(5)
	otherKey.SshKeyFingerprints = []string{"SHA256:someone-else"}

	tests := []struct {
		name    string
		set     []*pb.Warrant
		account string
		fp      string
		wantID  uint64
		reason  pb.UnwarrantedSessionEvent_Reason
	}{
		{"계정과 키가 맞다", []*pb.Warrant{warrant(1)}, "ec2-user", aliceFP, 1, 0},
		{"영장 없음", nil, "ec2-user", aliceFP, 0, pb.UnwarrantedSessionEvent_REASON_NO_WARRANT},
		{"다른 계정", []*pb.Warrant{warrant(1)}, "root", aliceFP, 0, pb.UnwarrantedSessionEvent_REASON_NO_WARRANT},
		{"남의 키", []*pb.Warrant{otherKey}, "ec2-user", aliceFP, 0, pb.UnwarrantedSessionEvent_REASON_KEY_MISMATCH},
		{"키 없음", []*pb.Warrant{warrant(1)}, "ec2-user", "", 0, pb.UnwarrantedSessionEvent_REASON_NO_KEY},
		{"만료 · 취소는 안 붙는다", []*pb.Warrant{expired, revoked}, "ec2-user", aliceFP, 0, pb.UnwarrantedSessionEvent_REASON_NO_WARRANT},
		{"여럿이면 늦게 끝나는 쪽", []*pb.Warrant{warrant(1), later}, "ec2-user", aliceFP, 4, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, reason := matchWarrant(tt.set, tt.account, tt.fp, now)
			if w.GetWarrantId() != tt.wantID || reason != tt.reason {
				t.Fatalf("got warrant %d reason %v, want %d %v", w.GetWarrantId(), reason, tt.wantID, tt.reason)
			}
		})
	}
}

// 맞는 영장이 있으면 세션 cgroup 에 붙이고, 무영장이 아니라 영장 세션으로 기록한다.
func TestBindTagsSessionWithMatchingWarrant(t *testing.T) {
	tg, s := &tagger{}, &sink{}
	b := &binder{maps: tg, audit: s, warrants: warrantList{warrant(9)}, now: func() time.Time { return now }}

	id, err := b.Bind(context.Background(), open(aliceKey))
	if err != nil {
		t.Fatal(err)
	}
	if id != 9 || tg.tagged[7594] != 9 {
		t.Fatalf("returned %d, tagged %v; want cgroup 7594 -> 9", id, tg.tagged)
	}
	if len(s.got) != 1 || s.got[0].GetWarrantedSession() == nil {
		t.Fatalf("queued %v, want one warranted session", s.got)
	}
}

// 「조직 전체 SSH 접속 현황」의 한 줄 — 누가 · 어디서 · 어느 키로 · 어느 영장으로. 서버 매퍼가 받는 모양이어야 한다.
func TestWarrantedEventSaysWhoCameInUnderWhichWarrant(t *testing.T) {
	e := warrantedEvent(open(aliceKey), aliceFP, warrant(9), now)

	if e.GetWallTsUnixNs() != uint64(now.UnixNano()) {
		t.Errorf("wall_ts = %d, want %d", e.GetWallTsUnixNs(), now.UnixNano())
	}
	if e.GetHook() != pb.Hook_HOOK_AGENT || e.GetOrigin() != pb.Origin_ORIGIN_AGENT || e.GetTagSource() != pb.TagSource_TAG_CGROUP {
		t.Errorf("hook %v origin %v tag %v", e.GetHook(), e.GetOrigin(), e.GetTagSource())
	}
	if e.GetVerdict() != pb.Verdict_VERDICT_ALLOW || e.GetWarrantId() != 9 || e.GetSubjectId() != 42 ||
		e.GetPolicyId() != 7 || e.GetMode() != pb.Mode_MODE_DRYRUN {
		t.Errorf("verdict %v warrant %d subject %d policy %d mode %v",
			e.GetVerdict(), e.GetWarrantId(), e.GetSubjectId(), e.GetPolicyId(), e.GetMode())
	}
	w := e.GetWarrantedSession()
	if w.GetLoginAccount() != "ec2-user" || w.GetSourceAddress() != "10.0.0.5" || w.GetCgroupId() != 7594 ||
		w.GetSessionId() != "c1" || w.GetSshKeyFingerprint() != aliceFP {
		t.Errorf("warranted session = %v", w)
	}
}

// 계정에는 영장이 있는데 키가 다르면 남의 영장에 편승하려는 것이다.
func TestBindRecordsKeyMismatch(t *testing.T) {
	w := warrant(9)
	w.SshKeyFingerprints = []string{"SHA256:someone-else"}
	tg, s := &tagger{}, &sink{}
	b := &binder{maps: tg, audit: s, warrants: warrantList{w}, now: func() time.Time { return now }}

	if _, err := b.Bind(context.Background(), open(aliceKey)); err != nil {
		t.Fatal(err)
	}
	if len(tg.tagged) != 0 {
		t.Fatalf("tagged %v", tg.tagged)
	}
	if len(s.got) != 1 || s.got[0].GetUnwarrantedSession().GetReason() != pb.UnwarrantedSessionEvent_REASON_KEY_MISMATCH {
		t.Fatalf("queued %v, want one KEY_MISMATCH", s.got)
	}
}

// 태그를 못 붙이면 세션은 커널 눈에 무영장이다. 숨기지 않고 기록한다.
func TestBindTagFailureIsRecordedAsUnwarranted(t *testing.T) {
	tg, s := &tagger{err: errors.New("map full")}, &sink{}
	b := &binder{maps: tg, audit: s, warrants: warrantList{warrant(9)}, now: func() time.Time { return now }}

	id, err := b.Bind(context.Background(), open(aliceKey))
	if err == nil || id != 0 {
		t.Fatalf("id %d err %v, want 0 and an error", id, err)
	}
	if len(s.got) != 1 || s.got[0].GetUnwarrantedSession().GetReason() != pb.UnwarrantedSessionEvent_REASON_NO_WARRANT {
		t.Fatalf("queued %v, want one NO_WARRANT", s.got)
	}
}

// cgroup id 를 못 구한 세션에는 붙일 곳이 없다.
func TestBindWithoutCgroupIsUnwarranted(t *testing.T) {
	tg, s := &tagger{}, &sink{}
	b := &binder{maps: tg, audit: s, warrants: warrantList{warrant(9)}, now: func() time.Time { return now }}
	r := open(aliceKey)
	r.CgroupID = 0

	if id, _ := b.Bind(context.Background(), r); id != 0 || len(tg.tagged) != 0 {
		t.Fatalf("id %d tagged %v", id, tg.tagged)
	}
	if len(s.got) != 1 {
		t.Fatalf("queued %d events, want 1", len(s.got))
	}
}

var _ pamsock.Binder = (*binder)(nil)
