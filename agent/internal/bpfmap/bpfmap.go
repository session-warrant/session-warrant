// Package bpfmap 은 BPF 맵의 유일한 진입점이다.
//
// # 소유와 경계
//
// A(커널) 소유 패키지다. B 의 upstream 은 맵을 직접 열지 않고 여기 함수만 부른다 —
// A ↔ B 의 경계는 gRPC 가 아니라 이 맵 레이아웃 하나다.
//
// 값 구조체는 proto/warrant.proto 에서 나온다. 커널 struct warrant 와 바이트가
// 어긋나면 디버깅이 지옥이 되므로, 필드를 여기서만 고치지 말고 .proto 를 먼저 고친다.
package bpfmap

// Warrant 는 커널 warrants 맵의 값이다. bpf/warrant.bpf.h 의 struct warrant 와
// 바이트 단위로 같아야 한다 — 오프셋 assert 테스트로 지킨다.
//
//	struct warrant {
//	    __u64 expires_ns;   // bpf_ktime_get_boot_ns 기준. 변환은 upstream 이 아니라 여기 오기 전에 끝난다
//	    __u64 grace_ns;     // on_expiry=2 일 때의 유예 기간
//	    __u32 subject_id;
//	    __u32 policy_id;    // 불변 정책 버전 id. rule_* 조회 키의 앞부분
//	    __u8  revoked;
//	    __u8  mode;         // 0 observe · 1 dryrun · 2 enforce
//	    __u8  on_expiry;
//	};
type Warrant struct {
	ExpiresNs uint64
	GraceNs   uint64
	SubjectID uint32
	PolicyID  uint32
	Revoked   uint8
	Mode      uint8
	OnExpiry  uint8
	_         [5]byte // 패딩. C 구조체와 크기를 맞춘다
}

// FileRef 는 rule_exec · rule_write 의 키 뒷부분이다.
//
// dev 를 빼면 안 된다. inode 번호는 파일시스템 안에서만 유일해서, tmpfs 에 같은 번호의
// 파일을 만들면 허용 목록을 통과한다. 기획서 §12 의 표는 (policy, inode) 로 적혀 있으나
// 실제 키는 (policy_id, dev, ino) 다.
type FileRef struct {
	Dev uint32
	Ino uint64
}

// Maps 는 pin 된 맵 묶음이다. 열기만 하고 만들지 않는 경로도 있다 —
// warrantd 재시작 중 태깅 공백이 생기면 안 되므로 맵은 bpffs 에 pin 된 것을 다시 연다.
type Maps struct{}

// Open 은 bpffs 의 pin 경로에서 맵을 연다. 없으면 loader 가 만든 뒤에 불러야 한다.
func Open(pinDir string) (*Maps, error) {
	panic("미구현")
}

// PutWarrant 는 warrants[id] 를 쓴다. expiresNs 는 이미 boot 기준으로 변환된 값이어야 한다.
func (m *Maps) PutWarrant(id uint64, w Warrant) error {
	panic("미구현")
}

// Revoke 는 revoked 한 바이트만 뒤집는다. 전체를 다시 쓰지 않는 이유는
// 그 사이 다른 필드가 갱신됐을 수 있기 때문이다.
func (m *Maps) Revoke(id uint64) error {
	panic("미구현")
}

// DeleteWarrant 는 만료·회수 뒤 정리용이다. 커널 판정은 이것 없이도 만료로 끊긴다 —
// 지우지 못해도 집행이 새지 않는다.
func (m *Maps) DeleteWarrant(id uint64) error {
	panic("미구현")
}

// TagCgroup 은 cgroup_warrant[cgroupID] = warrantID. 1차 바인딩이다(§04).
// pamsock 이 PAM 세션 시작 시점에 부른다.
func (m *Maps) TagCgroup(cgroupID, warrantID uint64) error {
	panic("미구현")
}

// UntagCgroup 은 세션 종료(PAM close_session) 때 부른다. S3 에서 그 시점에
// scope 가 아직 살아 있음을 확인했다. nohup 으로 살아남은 프로세스는
// task_warrant 쪽 태그를 계속 들고 있다 — 의도된 동작이다.
func (m *Maps) UntagCgroup(cgroupID uint64) error {
	panic("미구현")
}

// PutExecRule · PutWriteRule · PutNetRule 은 policy 가 컴파일한 결과를 쓴다.
// 같은 policyID 에 내용이 다른 규칙이 오면 upstream 이 여기까지 보내기 전에 거부한다.
func (m *Maps) PutExecRule(policyID uint32, f FileRef) error { panic("미구현") }
func (m *Maps) PutWriteRule(policyID uint32, f FileRef, allow bool, recursive bool) error {
	panic("미구현")
}
func (m *Maps) PutNetRule(policyID uint32, cidr string, port uint16, proto uint8) error {
	panic("미구현")
}

// SetActive 는 active_flag 를 올린다. 이 노드에 활성 영장이 하나도 없으면
// 모든 훅이 즉시 통과한다 — 평시 오버헤드를 0 에 가깝게 만드는 장치(§12).
func (m *Maps) SetActive(active bool) error {
	panic("미구현")
}
