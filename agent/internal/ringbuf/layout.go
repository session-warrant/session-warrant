package ringbuf

// ringbuf 레코드의 바이트 레이아웃. bpf/warrant.bpf.h 와 1:1 이다.
//
// 커널은 고정 머리(evtHeader) 를 쓰고 그 뒤에 PayloadLen 바이트의 payload 를 붙인다.
// Hook 값이 payload 가 어느 구조체인지 정한다.
//
// Record (이 패키지의 공개 타입) 는 이 레이아웃을 풀어낸 결과다 —
// 소비자는 evtHeader 를 보지 않는다.

type proc struct {
	StartTimeNs uint64 // (pid, start_time) 이 유일 키
	CgroupID    uint64
	PID         uint32
	TGID        uint32
	PPID        uint32
	UID         uint32
	EUID        uint32
	GID         uint32
	PIDNsInum   uint32 // exit 중이면 0
	_           uint32
	Comm        [16]byte // 잘리고 위조 가능하다. 1급 증거가 아니다
}

type evtHeader struct {
	CPUSeq     uint64
	BootTsNs   uint64 // bpf_ktime_get_boot_ns(). 벽시계 변환은 warrantd 가 한다
	WarrantID  uint64 // 0 = 무영장
	CPU        uint32
	SubjectID  uint32
	PolicyID   uint32
	Hook       uint16
	Verdict    uint8
	Mode       uint8
	Origin     uint8 // lsm 과 kprobe 미러의 판정이 다르면 버그
	TagSource  uint8
	PayloadLen uint16
	_          [4]byte
	Proc       proc
}

type fileRef struct {
	Dev uint32
	_   uint32
	Ino uint64
}

type plExec struct {
	File    fileRef
	IMode   uint32 // setuid 탐지
	NewUID  uint32
	NewEUID uint32
	_       uint32
}

type plWrite struct {
	File   fileRef
	Parent fileRef
	FFlags uint32 // O_TRUNC · O_APPEND · O_CREAT
	_      uint32
}

type plInode struct {
	Dir    fileRef
	Target fileRef
	Op     uint8
	_      [7]byte
}

type plConnect struct {
	Family uint8 // 1 UNIX · 2 INET · 10 INET6
	Proto  uint8
	Port   uint16 // host byte order
	_      uint32
	Addr   [16]byte // 네트워크 바이트 오더
}

type plFork struct {
	ParentTGID    uint32
	ChildTGID     uint32
	ChildCgroupID uint64
}

// proto/audit.proto enum Hook 과 값이 같다.
const (
	HookSchedProcessFork  uint16 = 1
	HookBprmCheckSecurity uint16 = 2
	HookSocketConnect     uint16 = 3
	HookFileOpen          uint16 = 4
	HookInodeCreate       uint16 = 5
	HookInodeUnlink       uint16 = 6
	HookInodeRename       uint16 = 7
	HookInodeLink         uint16 = 8
	HookInodeSymlink      uint16 = 9
	HookBPF               uint16 = 10
	HookTaskKill          uint16 = 11
	HookSbUmount          uint16 = 12
	HookPtraceAccessCheck uint16 = 13
	HookKernelModuleReq   uint16 = 14
	HookSocketSendmsg     uint16 = 15
)
