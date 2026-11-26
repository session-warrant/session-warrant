package store

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/session-warrant/session-warrant/agent/internal/pb"
	"github.com/session-warrant/session-warrant/agent/internal/upstream"
)

// Store must drop in where AuditQueue is used today: upstream.StreamAudit and warrantd's binder/kernelUpload.
var (
	_ upstream.AuditSource = (*Store)(nil)
	_ interface {
		Append(*pb.AuditEvent) uint64
		AppendGap(*pb.GapReport)
	} = (*Store)(nil)
)

func open(t *testing.T, path string, maxEvents int) *Store {
	t.Helper()
	s, err := Open(path, maxEvents, 100)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// crash stops s the way a killed process would: no final flush, no clean marker.
func crash(t *testing.T, s *Store) {
	t.Helper()
	s.once.Do(func() {
		close(s.stop)
		<-s.done
		if err := s.db.Close(); err != nil {
			t.Fatal(err)
		}
	})
}

func next(t *testing.T, s *Store, after uint64) *pb.AuditBatch {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	b, err := s.Next(ctx, after)
	if err != nil {
		t.Fatalf("Next(after=%d): %v", after, err)
	}
	return b
}

func dbPath(t *testing.T) string {
	return filepath.Join(t.TempDir(), "warrantd.db")
}

// 세대 번호는 파일과 함께 산다 — 재시작해도 같아야 서버가 다시 보낸 기록을 중복으로 알아본다.
func TestStoreKeepsEpochAcrossRestart(t *testing.T) {
	path := dbPath(t)
	s := open(t, path, 10)
	epoch := s.SeqEpoch()
	if epoch == 0 {
		t.Fatal("epoch is 0")
	}
	s.Close()

	s = open(t, path, 10)
	defer s.Close()
	if s.SeqEpoch() != epoch {
		t.Fatalf("epoch changed across restart: %d → %d", epoch, s.SeqEpoch())
	}
}

// ack 안 된 기록은 정상 재시작을 넘기고, 번호는 끊김 없이 이어진다.
func TestStoreKeepsUnackedEventsAcrossCleanRestart(t *testing.T) {
	path := dbPath(t)
	s := open(t, path, 10)
	for i := uint64(1); i <= 3; i++ {
		s.Append(ev(i))
	}
	s.Close()

	s = open(t, path, 10)
	defer s.Close()
	if b := next(t, s, 0); !equal(seqs(b), []uint64{1, 2, 3}) || len(b.GetGaps()) != 0 {
		t.Fatalf("after restart: seqs %v gaps %v", seqs(b), b.GetGaps())
	}
	if got := s.Append(ev(4)); got != 4 {
		t.Fatalf("next seq after clean restart = %d, want 4", got)
	}
}

// 서버가 받은 만큼은 재시작 뒤에 다시 나오지 않는다.
func TestStoreForgetsAckedEvents(t *testing.T) {
	path := dbPath(t)
	s := open(t, path, 10)
	for i := uint64(1); i <= 4; i++ {
		s.Append(ev(i))
	}
	if err := s.flush(); err != nil { // the acked events are on disk before the ack, as in real life
		t.Fatal(err)
	}
	s.Ack(s.SeqEpoch(), 2)
	s.Close()

	s = open(t, path, 10)
	defer s.Close()
	if b := next(t, s, 0); !equal(seqs(b), []uint64{3, 4}) {
		t.Fatalf("after ack 2 and restart: %v, want [3 4]", seqs(b))
	}
}

// 비정상 종료: 마지막 flush 뒤의 기록은 잃는다. 대신 번호를 다시 쓰지 않고, 그 구간을 AGENT_DOWN 으로 남긴다.
// 번호를 다시 쓰면 서버가 이미 받은 옛 기록과 키가 같아져 새 기록을 중복으로 버린다.
func TestStoreCrashNeverReusesSeqAndReportsGap(t *testing.T) {
	path := dbPath(t)
	s := open(t, path, 100)
	for i := uint64(1); i <= 3; i++ {
		s.Append(ev(i))
	}
	if err := s.flush(); err != nil {
		t.Fatal(err)
	}
	for i := uint64(4); i <= 6; i++ {
		s.Append(ev(i)) // handed out — maybe already sent — but never flushed
	}
	crash(t, s)

	s = open(t, path, 100)
	defer s.Close()
	b := next(t, s, 0)
	if !equal(seqs(b), []uint64{1, 2, 3}) {
		t.Fatalf("survivors = %v, want [1 2 3]", seqs(b))
	}

	seq := s.Append(ev(7))
	if seq <= 6 {
		t.Fatalf("seq %d after a crash reuses a number that may have reached the server", seq)
	}
	b = next(t, s, 3)
	if len(b.GetGaps()) != 1 || b.GetGaps()[0].GetCause() != pb.GapReport_CAUSE_AGENT_DOWN ||
		b.GetGaps()[0].GetDroppedCountKnown() {
		t.Fatalf("gaps after crash = %v, want one AGENT_DOWN with unknown count", b.GetGaps())
	}
}

// 두 번 연달아 죽어도 번호는 뒤로 가지 않는다.
func TestStoreSeqKeepsClimbingOverRepeatedCrashes(t *testing.T) {
	path := dbPath(t)
	var last uint64
	for range 3 {
		s := open(t, path, 100)
		seq := s.Append(ev(1))
		if seq <= last {
			t.Fatalf("seq went from %d to %d", last, seq)
		}
		last = seq
		crash(t, s)
	}
}

// 상한을 넘겨 버린 구간(LOCAL_STORE_FULL)도 디스크에 남는다.
func TestStoreKeepsOverflowGapAcrossRestart(t *testing.T) {
	path := dbPath(t)
	s := open(t, path, 2)
	for i := uint64(1); i <= 4; i++ {
		s.Append(ev(i))
	}
	s.Close()

	s = open(t, path, 2)
	defer s.Close()
	b := next(t, s, 0)
	if !equal(seqs(b), []uint64{3, 4}) {
		t.Fatalf("seqs = %v, want [3 4]", seqs(b))
	}
	if len(b.GetGaps()) != 1 || b.GetGaps()[0].GetCause() != pb.GapReport_CAUSE_LOCAL_STORE_FULL ||
		b.GetGaps()[0].GetDroppedCount() != 2 {
		t.Fatalf("gaps = %v, want LOCAL_STORE_FULL ×2", b.GetGaps())
	}
}

// 커널 쪽 유실 보고도 재시작을 넘겨 다음 묶음에 실린다.
func TestStoreKeepsAppendedGapAcrossRestart(t *testing.T) {
	path := dbPath(t)
	s := open(t, path, 10)
	s.AppendGap(&pb.GapReport{Cause: pb.GapReport_CAUSE_RINGBUF_OVERFLOW, DroppedCount: 9, DroppedCountKnown: true})
	s.Append(ev(1))
	s.Close()

	s = open(t, path, 10)
	defer s.Close()
	b := next(t, s, 0)
	if len(b.GetGaps()) != 1 || b.GetGaps()[0].GetCause() != pb.GapReport_CAUSE_RINGBUF_OVERFLOW {
		t.Fatalf("gaps = %v", b.GetGaps())
	}
}

// 상한을 줄여 다시 열면 오래된 것부터 버리고 그것도 구간으로 남긴다.
func TestStoreShrinkingLimitDropsOldest(t *testing.T) {
	path := dbPath(t)
	s := open(t, path, 10)
	for i := uint64(1); i <= 5; i++ {
		s.Append(ev(i))
	}
	s.Close()

	s = open(t, path, 2)
	defer s.Close()
	b := next(t, s, 0)
	if !equal(seqs(b), []uint64{4, 5}) || len(b.GetGaps()) != 1 {
		t.Fatalf("seqs %v gaps %v, want [4 5] and one gap", seqs(b), b.GetGaps())
	}
}

// 영장 봉투는 받은 바이트 그대로 돌려준다. 옛 revision 은 새 것을 덮지 못한다.
func TestStoreWarrantCache(t *testing.T) {
	path := dbPath(t)
	s := open(t, path, 10)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(s.PutWarrant(7, 2, []byte("rev2")))
	must(s.PutWarrant(7, 1, []byte("rev1-late")))
	must(s.PutWarrant(8, 1, []byte("other")))
	must(s.PutWarrant(9, 1, []byte("gone")))
	must(s.DeleteWarrantsNotIn(map[uint64]struct{}{7: {}, 8: {}}))
	s.Close()

	s = open(t, path, 10)
	defer s.Close()
	got, err := s.Warrants()
	must(err)
	if len(got) != 2 || !bytes.Equal(got[7], []byte("rev2")) || !bytes.Equal(got[8], []byte("other")) {
		t.Fatalf("warrants = %q", got)
	}
}

// 다른 프로세스가 같은 파일을 쥐고 있으면 기다리다 실패한다 — 두 warrantd 가 한 파일을 나눠 쓰지 않는다.
func TestStoreRefusesSecondOpener(t *testing.T) {
	path := dbPath(t)
	s := open(t, path, 10)
	defer s.Close()
	if _, err := Open(path, 10, 10); err == nil {
		t.Fatal("second Open of the same file succeeded")
	}
}

// StreamAudit 이 쓰는 방식 그대로: 보내는 쪽이 기다리는 동안 Append 가 깨운다.
func TestStoreNextWakesOnAppend(t *testing.T) {
	s := open(t, dbPath(t), 10)
	defer s.Close()
	got := make(chan *pb.AuditBatch, 1)
	go func() {
		b, _ := s.Next(context.Background(), 0)
		got <- b
	}()
	time.Sleep(20 * time.Millisecond)
	s.Append(ev(1))
	select {
	case b := <-got:
		if !equal(seqs(b), []uint64{1}) {
			t.Fatalf("seqs = %v", seqs(b))
		}
	case <-time.After(time.Second):
		t.Fatal("Next did not wake on Append")
	}
}
