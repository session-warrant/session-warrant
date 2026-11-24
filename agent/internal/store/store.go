// Package store 는 bbolt 로컬 보관소다. 중앙이 끊긴 동안의 영장과 감사를 들고 있는다.
//
// 하는 일:
//   - Append · AppendGap · Next · Ack · SeqEpoch: AuditQueue 와 같은 감사 큐를 bbolt 에 비춰
//     warrantd 가 재시작해도 ack 안 된 기록과 seq_epoch 를 이어 간다 (upstream.AuditSource)
//   - PutWarrant · Warrants · DeleteWarrantsNotIn: 서명된 영장을 보관하고 재시작 때 돌려준다
//   - AuditQueue (auditqueue.go): 메모리 큐. Store 가 이걸 감싼다
//
// 쓰기는 모아서 한다(flushEvery 마다 한 트랜잭션). 감사 이벤트마다 fsync 하면 커널 이벤트 속도를 못 따라간다.
// 그래서 정상 종료(Close)가 아니면 마지막 flush 뒤의 기록을 잃을 수 있고, 다음 Open 이 그 구간을
// AGENT_DOWN 으로 남긴다 — 빈 구간을 숨기지 않는다(§13).
//
// 부르는 쪽: cmd/warrantd 기동 2단계, upstream.StreamAudit. 상태: 구현. warrantd 연결은 C 의 몫이다.
package store

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"

	"github.com/session-warrant/session-warrant/agent/internal/pb"
)

var (
	bucketMeta     = []byte("meta")
	bucketAudit    = []byte("audit")    // node_seq (big-endian u64) → AuditEvent
	bucketGaps     = []byte("gaps")     // index → beforeSeq (u64) + GapReport. Rewritten whole on every flush
	bucketWarrants = []byte("warrants") // warrant_id (big-endian u64) → revision (u32) + signed envelope

	keyEpoch     = []byte("seq_epoch")
	keySeqLimit  = []byte("seq_limit")  // no node_seq at or above this was handed out
	keyCleanNext = []byte("clean_next") // written by Close only: the exact next node_seq
	keyFlushedAt = []byte("flushed_at") // wall clock of the last flush, the start of an AGENT_DOWN gap
)

const flushEvery = 200 * time.Millisecond

// Store is safe for concurrent use. Close it on shutdown; skipping Close is treated as a crash.
type Store struct {
	db *bolt.DB
	q  *AuditQueue

	flushMu        sync.Mutex
	flushedThrough uint64 // highest node_seq written to disk

	stop chan struct{}
	done chan struct{}
	once sync.Once
}

// Open restores the queue from path (creating it on first use) and starts writing it back every flushEvery.
// maxEvents and maxBatch mean what they mean for NewAuditQueue.
func Open(path string, maxEvents, maxBatch int) (*Store, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	s := &Store{db: db, stop: make(chan struct{}), done: make(chan struct{})}
	if s.q, err = s.restore(maxEvents, maxBatch, time.Now()); err != nil {
		db.Close()
		return nil, err
	}
	s.q.reserve = s.reserveSeq
	go s.flushLoop()
	return s, nil
}

func (s *Store) restore(maxEvents, maxBatch int, now time.Time) (*AuditQueue, error) {
	q := NewAuditQueue(maxEvents, maxBatch)
	err := s.db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bucketMeta, bucketAudit, bucketGaps, bucketWarrants} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		meta := tx.Bucket(bucketMeta)

		if e := getU64(meta, keyEpoch); e != 0 {
			q.epoch = e
		} else if err := putU64(meta, keyEpoch, q.epoch); err != nil {
			return err
		}
		q.seqLimit = getU64(meta, keySeqLimit)

		if err := tx.Bucket(bucketAudit).ForEach(func(k, v []byte) error {
			e := &pb.AuditEvent{}
			if err := proto.Unmarshal(v, e); err != nil {
				return fmt.Errorf("audit event %d: %w", binary.BigEndian.Uint64(k), err)
			}
			q.events = append(q.events, e) // ForEach walks keys in order, so seqs stay ascending
			return nil
		}); err != nil {
			return err
		}
		if err := tx.Bucket(bucketGaps).ForEach(func(_, v []byte) error {
			g := &pb.GapReport{}
			if len(v) < 8 {
				return errors.New("gap record too short")
			}
			if err := proto.Unmarshal(v[8:], g); err != nil {
				return fmt.Errorf("gap: %w", err)
			}
			q.gaps = append(q.gaps, queuedGap{beforeSeq: binary.BigEndian.Uint64(v), gap: g})
			return nil
		}); err != nil {
			return err
		}

		switch clean := getU64(meta, keyCleanNext); {
		case clean != 0:
			// Closed cleanly: carry on with the very next number. The marker is spent, so a later crash shows.
			q.nextSeq = clean
			if err := meta.Delete(keyCleanNext); err != nil {
				return err
			}
		case q.seqLimit != 0:
			// Crashed: events after the last flush are gone and their numbers may have reached the server.
			// Start above everything that could have been handed out, and say the records may have a hole.
			q.nextSeq = q.seqLimit
			from := getU64(meta, keyFlushedAt)
			if from == 0 {
				from = uint64(now.UnixNano())
			}
			q.gaps = append(q.gaps, queuedGap{beforeSeq: q.nextSeq, gap: &pb.GapReport{
				FromUnixNs: from,
				ToUnixNs:   uint64(now.UnixNano()),
				Cause:      pb.GapReport_CAUSE_AGENT_DOWN,
			}})
		}
		if n := len(q.events); n > 0 && q.events[n-1].NodeSeq >= q.nextSeq {
			return fmt.Errorf("stored event %d is at or past the next node_seq %d", q.events[n-1].NodeSeq, q.nextSeq)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("store: restore: %w", err)
	}

	s.flushedThrough = q.nextSeq - 1
	for len(q.events) > q.maxEvents { // the limit may have shrunk since the last run
		q.dropOldest()
	}
	return q, nil
}

// Called by AuditQueue.Append with the queue lock held. Synchronous, once per seqReserveBlock events.
func (s *Store) reserveSeq(limit uint64) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return putU64(tx.Bucket(bucketMeta), keySeqLimit, limit)
	})
}

func (s *Store) flushLoop() {
	defer close(s.done)
	t := time.NewTicker(flushEvery)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			if err := s.flush(); err != nil {
				log.Printf("store: flush: %v", err)
			}
		}
	}
}

// flush makes the disk match the queue: drops what was acked or overflowed, adds what is new, rewrites the gaps.
func (s *Store) flush() error {
	s.flushMu.Lock()
	defer s.flushMu.Unlock()

	head, fresh, gaps := s.q.snapshot(s.flushedThrough)
	err := s.db.Update(func(tx *bolt.Tx) error {
		audit := tx.Bucket(bucketAudit)
		var gone [][]byte
		c := audit.Cursor()
		for k, _ := c.First(); k != nil && binary.BigEndian.Uint64(k) < head; k, _ = c.Next() {
			gone = append(gone, k)
		}
		if err := deleteKeys(audit, gone); err != nil {
			return err
		}
		for _, e := range fresh {
			v, err := proto.Marshal(e)
			if err != nil {
				return err
			}
			if err := audit.Put(u64(e.NodeSeq), v); err != nil {
				return err
			}
		}

		if err := tx.DeleteBucket(bucketGaps); err != nil {
			return err
		}
		gb, err := tx.CreateBucket(bucketGaps)
		if err != nil {
			return err
		}
		for i, g := range gaps {
			v, err := proto.Marshal(g.gap)
			if err != nil {
				return err
			}
			if err := gb.Put(u64(uint64(i)), append(u64(g.beforeSeq), v...)); err != nil {
				return err
			}
		}
		return putU64(tx.Bucket(bucketMeta), keyFlushedAt, uint64(time.Now().UnixNano()))
	})
	if err != nil {
		return err
	}
	if n := len(fresh); n > 0 {
		s.flushedThrough = fresh[n-1].NodeSeq
	}
	return nil
}

// Close writes everything down and marks the stop as clean, so the next Open reports no gap.
func (s *Store) Close() error {
	var err error
	s.once.Do(func() {
		close(s.stop)
		<-s.done
		err = s.flush()
		if err == nil {
			s.q.mu.Lock()
			next := s.q.nextSeq
			s.q.mu.Unlock()
			err = s.db.Update(func(tx *bolt.Tx) error {
				return putU64(tx.Bucket(bucketMeta), keyCleanNext, next)
			})
		}
		if cerr := s.db.Close(); err == nil {
			err = cerr
		}
	})
	return err
}

// ---------------------------------------------------------------- 감사 큐 (upstream.AuditSource)

// SeqEpoch is drawn once when the file is created and kept for its life, so the server's idempotency key
// (node_id, seq_epoch, node_seq) recognises events resent after a restart.
func (s *Store) SeqEpoch() uint64 { return s.q.SeqEpoch() }

// Append numbers e and keeps it until acked. It reaches disk on the next flush.
func (s *Store) Append(e *pb.AuditEvent) uint64 { return s.q.Append(e) }

func (s *Store) AppendGap(g *pb.GapReport) { s.q.AppendGap(g) }

func (s *Store) Next(ctx context.Context, after uint64) (*pb.AuditBatch, error) {
	return s.q.Next(ctx, after)
}

// Ack drops everything through nodeSeq. The disk catches up on the next flush; an ack lost to a crash only
// means the server gets those events again and drops them as duplicates.
func (s *Store) Ack(seqEpoch, nodeSeq uint64) error { return s.q.Ack(seqEpoch, nodeSeq) }

// ---------------------------------------------------------------- 영장 캐시

// PutWarrant keeps the envelope byte for byte; re-serializing would break the signature. An older revision
// than the one held is ignored, so a late message cannot roll a warrant back.
func (s *Store) PutWarrant(warrantID uint64, revision uint32, signedEnvelope []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketWarrants)
		if old := b.Get(u64(warrantID)); len(old) >= 4 && binary.BigEndian.Uint32(old) > revision {
			return nil
		}
		v := make([]byte, 4, 4+len(signedEnvelope))
		binary.BigEndian.PutUint32(v, revision)
		return b.Put(u64(warrantID), append(v, signedEnvelope...))
	})
}

// Warrants returns the held envelopes by warrant_id. The caller verifies them again before use.
func (s *Store) Warrants() (map[uint64][]byte, error) {
	out := map[uint64][]byte{}
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketWarrants).ForEach(func(k, v []byte) error {
			if len(v) < 4 {
				return fmt.Errorf("warrant %d: record too short", binary.BigEndian.Uint64(k))
			}
			out[binary.BigEndian.Uint64(k)] = append([]byte(nil), v[4:]...) // v is only valid inside the tx
			return nil
		})
	})
	return out, err
}

// DeleteWarrantsNotIn drops every held warrant outside active — called on ResyncComplete.
func (s *Store) DeleteWarrantsNotIn(active map[uint64]struct{}) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketWarrants)
		var gone [][]byte
		c := b.Cursor()
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			if _, ok := active[binary.BigEndian.Uint64(k)]; !ok {
				gone = append(gone, k)
			}
		}
		return deleteKeys(b, gone)
	})
}

// ---------------------------------------------------------------- 인코딩

// Deleting under a live cursor makes bbolt's Next skip the following key, so keys are collected first.
// Keys from a cursor stay valid until the transaction ends.
func deleteKeys(b *bolt.Bucket, keys [][]byte) error {
	for _, k := range keys {
		if err := b.Delete(k); err != nil {
			return err
		}
	}
	return nil
}

func u64(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}

func getU64(b *bolt.Bucket, k []byte) uint64 {
	if v := b.Get(k); len(v) == 8 {
		return binary.BigEndian.Uint64(v)
	}
	return 0
}

func putU64(b *bolt.Bucket, k []byte, v uint64) error {
	return b.Put(k, u64(v))
}
