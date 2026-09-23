// Package loader 는 BPF 오브젝트를 로드하고 bpffs 에 pin 하고 훅을 attach 한다.
//
// A(커널) 소유. 훅은 한 번에 하나씩 붙인다 —
// sched_process_fork → bprm_check_security → socket_connect → file_open →
// inode_{create,unlink,rename,link,symlink} → 자기보호 6종 → socket_sendmsg → kprobe 미러.
// 훅 하나마다 verifier 통과와 오버헤드를 같이 확인한다.
package loader

// Loader 는 프로그램·맵의 수명을 들고 있다.
type Loader struct{}

// Load 는 bpf2go 생성물을 커널에 올린다. 맵이 이미 bpffs 에 pin 돼 있으면
// 그것을 재사용한다 — warrantd 가 재시작해도 태그가 날아가면 안 된다.
func Load(pinDir string) (*Loader, error) {
	panic("미구현")
}

// AttachAll 은 지금 빌드에 포함된 훅을 전부 붙인다.
//
// 스파이크·이번 학기 전 구간은 감사 모드다. LSM 훅은 return 0 만 한다 —
// 자기보호 6종(§16)을 붙이기 전에 -EPERM 을 켜면 verifier 를 통과한 버그 하나로
// 자기 박스에서 잠긴다.
func (l *Loader) AttachAll() error {
	panic("미구현")
}

// AttachedHooks 는 지금 붙어 있는 훅 이름을 돌려준다.
// NodeHello.attached_hooks 로 중앙에 올라간다 — 서버가 "이 노드는 file_open 을 아직 안 본다"를
// 알아야 빈 데이터를 "아무 일 없음"으로 오해하지 않는다.
func (l *Loader) AttachedHooks() []string {
	panic("미구현")
}

// Close 는 프로그램 링크를 닫는다. pin 은 지우지 않는다 —
// 지우면 다음 기동까지 태깅 공백이 생긴다.
func (l *Loader) Close() error {
	panic("미구현")
}

// BpfLsmEnabled 는 /sys/kernel/security/lsm 에 bpf 가 있는지 본다.
// 없으면 ENFORCE 영장을 받아도 강제되지 않는다 — 그 사실을 NodeHello 로 올린다.
func BpfLsmEnabled() (bool, error) {
	panic("미구현")
}
