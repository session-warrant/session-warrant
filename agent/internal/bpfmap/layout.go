package bpfmap

// 맵 키·값의 바이트 레이아웃. bpf/warrant.bpf.h 와 1:1 이다.
//
// 이 파일에는 변환 로직을 넣지 않는다. 레이아웃만 둔다.
// 크기가 어긋나면 맵 조회가 에러 없이 빗나가므로 layout_test.go 가 크기를 고정한다.
// C 쪽은 같은 숫자를 warrant.bpf.h 의 _Static_assert 가 막는다.

// ruleKey 는 rule_exec · rule_write 의 키다.
//
// Dev 는 커널 s_dev 다 — 유저 공간 st_dev 와 인코딩이 다르다.
// FileRef 를 만들 때 major<<20 | minor 로 바꿔 넣는다. 이 변환을 빠뜨리면
// 조회가 전건 miss 가 되고, 에러는 나지 않는다.
type ruleKey struct {
	PolicyID uint32
	Dev      uint32
	Ino      uint64
}

// writeVal 은 rule_write 의 값이다. 최장 일치 → 같은 깊이면 DENY → 안 걸리면 금지.
type writeVal struct {
	Effect    uint8 // EffectAllow · EffectDeny
	Recursive uint8
	_         [6]byte
}

const (
	EffectAllow uint8 = 1
	EffectDeny  uint8 = 2
)

// netKey 는 rule_net (LPM_TRIE) 의 키다.
//
// PolicyIDBE 는 big-endian 이어야 한다 — LPM 은 MSB 부터 맞추므로
// host order 로 넣으면 엉뚱한 정책에 걸린다.
// PrefixLen = 32 + CIDR 비트수. IPv4 는 ::ffff:a.b.c.d 로 펴서 넣는다.
type netKey struct {
	PrefixLen  uint32
	PolicyIDBE uint32
	Addr       [16]byte
}

// netVal 의 NPorts = 0 이면 모든 포트다.
type netVal struct {
	Proto  uint8 // 0 ANY · 1 TCP · 2 UDP
	NPorts uint8
	Ports  [7]uint16
}
