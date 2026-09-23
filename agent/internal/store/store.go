// Package store 는 bbolt 로컬 보관소다. 중앙이 끊긴 동안의 영장과 감사를 들고 있는다.
//
// B(서버·계약) 소유.
package store

// Store 는 bbolt 핸들이다.
type Store struct{}

// Open 은 DB 를 연다. 처음 만들 때 seq epoch 를 새로 뽑는다 — SeqEpoch 주석 참조.
func Open(path string) (*Store, error) {
	panic("미구현")
}

// SeqEpoch 는 이 DB 가 만들어질 때 뽑은 난수다.
//
// 서버의 감사 멱등 키는 (node_id, seq_epoch, node_seq) 다. epoch 가 없으면
// DB 가 날아가 node_seq 가 1 로 되돌아갔을 때 서버가 새 이벤트를 중복으로 보고
// 조용히 버린다 — "빈 구간을 숨기지 않는다"의 정면 위반이다.
func (s *Store) SeqEpoch() uint64 {
	panic("미구현")
}

// NextNodeSeq 는 감사 이벤트에 붙일 단조 증가 번호를 준다.
func (s *Store) NextNodeSeq() (uint64, error) {
	panic("미구현")
}

// PutWarrant 는 서명 봉투를 바이트 그대로 보관한다. 재직렬화하면 서명이 깨진다.
func (s *Store) PutWarrant(warrantID uint64, revision uint32, signedEnvelope []byte) error {
	panic("미구현")
}

// Warrants 는 기동 시 맵을 복원할 때 쓴다. 중앙이 안 떠 있어도 집행은 이어진다.
func (s *Store) Warrants() (map[uint64][]byte, error) {
	panic("미구현")
}

// DeleteWarrantsNotIn 은 ResyncComplete 에서 활성 집합 밖의 캐시를 지운다.
func (s *Store) DeleteWarrantsNotIn(active map[uint64]struct{}) error {
	panic("미구현")
}

// AppendAudit 는 업로드 전 이벤트를 쌓는다. 상한을 넘으면 오래된 것부터 버리고
// 버린 구간을 GapReport(LOCAL_STORE_FULL)로 남긴다 — 조용히 버리지 않는다.
func (s *Store) AppendAudit(nodeSeq uint64, event []byte) error {
	panic("미구현")
}

// AckThrough 는 서버가 적재한 지점까지 지운다.
func (s *Store) AckThrough(seqEpoch, nodeSeq uint64) error {
	panic("미구현")
}
