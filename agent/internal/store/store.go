// Package store 는 bbolt 로컬 보관소다. 중앙이 끊긴 동안의 영장과 감사를 들고 있는다.
//
// 하는 일:
//   - PutWarrant · Warrants · DeleteWarrantsNotIn: 서명된 영장을 보관하고 재시작 때 돌려준다
//   - AppendAudit · AckThrough: 아직 못 보낸 감사 이벤트를 쌓고, 서버가 받은 만큼 지운다
//   - SeqEpoch · NextNodeSeq: 감사 이벤트 순번을 매긴다
//   - AuditQueue (auditqueue.go): 감사 절반의 메모리 대역. bbolt 전까지 이걸 쓴다
//
// 부르는 쪽: cmd/warrantd 기동 2단계, upstream. 상태: AuditQueue 만 구현, bbolt Store 는 미구현 (B 담당).
package store

type Store struct{}

func Open(path string) (*Store, error) {
	panic("미구현")
}

// SeqEpoch 는 DB 를 처음 만들 때 뽑은 난수다. node_seq 가 1 로 돌아가도 서버의
// 멱등 키 (node_id, seq_epoch, node_seq) 가 옛 것과 겹치지 않게 한다.
func (s *Store) SeqEpoch() uint64 {
	panic("미구현")
}

func (s *Store) NextNodeSeq() (uint64, error) {
	panic("미구현")
}

// PutWarrant 는 봉투를 받은 바이트 그대로 보관한다. 재직렬화하면 서명이 깨진다.
func (s *Store) PutWarrant(warrantID uint64, revision uint32, signedEnvelope []byte) error {
	panic("미구현")
}

func (s *Store) Warrants() (map[uint64][]byte, error) {
	panic("미구현")
}

func (s *Store) DeleteWarrantsNotIn(active map[uint64]struct{}) error {
	panic("미구현")
}

// AppendAudit 는 상한을 넘으면 오래된 것부터 버리고 그 구간을 Gap(LOCAL_STORE_FULL)으로 남긴다.
func (s *Store) AppendAudit(nodeSeq uint64, event []byte) error {
	panic("미구현")
}

func (s *Store) AckThrough(seqEpoch, nodeSeq uint64) error {
	panic("미구현")
}
