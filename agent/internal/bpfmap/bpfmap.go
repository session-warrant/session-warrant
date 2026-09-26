// Package bpfmap 은 BPF 맵의 유일한 진입점이다. 다른 패키지는 맵을 직접 열지 않는다.
package bpfmap

// Warrant 는 warrants 맵의 값. bpf/warrant.bpf.h 의 struct warrant 와 바이트 단위로 같아야 한다.
// 필드는 proto/warrant.proto 를 먼저 고친다.
type Warrant struct {
	ExpiresNs uint64 // boot 기준
	GraceNs   uint64
	SubjectID uint32
	PolicyID  uint32
	Revoked   uint8
	Mode      uint8
	OnExpiry  uint8
	_         [5]byte // C 구조체와 크기를 맞추는 패딩
}

// FileRef 는 rule_* 키의 뒷부분. inode 번호는 파일시스템 안에서만 유일하므로 dev 를 빼면 안 된다.
type FileRef struct {
	Dev uint32
	Ino uint64
}

type Maps struct{}

func Open(pinDir string) (*Maps, error) {
	panic("미구현")
}

// PutWarrant 의 w.ExpiresNs 는 이미 boot 기준으로 변환된 값이어야 한다.
func (m *Maps) PutWarrant(id uint64, w Warrant) error {
	panic("미구현")
}

// Revoke 는 revoked 한 바이트만 뒤집는다.
func (m *Maps) Revoke(id uint64) error {
	panic("미구현")
}

func (m *Maps) DeleteWarrant(id uint64) error {
	panic("미구현")
}

func (m *Maps) TagCgroup(cgroupID, warrantID uint64) error {
	panic("미구현")
}

func (m *Maps) UntagCgroup(cgroupID uint64) error {
	panic("미구현")
}

func (m *Maps) PutExecRule(policyID uint32, f FileRef) error { panic("미구현") }
func (m *Maps) PutWriteRule(policyID uint32, f FileRef, allow bool, recursive bool) error {
	panic("미구현")
}
func (m *Maps) PutNetRule(policyID uint32, cidr string, port uint16, proto uint8) error {
	panic("미구현")
}

// SetActive(false) 면 모든 훅이 즉시 통과한다.
func (m *Maps) SetActive(active bool) error {
	panic("미구현")
}
