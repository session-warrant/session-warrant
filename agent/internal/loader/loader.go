// Package loader 는 BPF 오브젝트를 로드하고 bpffs 에 pin 하고 훅을 attach 한다.
//
// 하는 일:
//   - Load: pin 된 프로그램 · 맵이 있으면 재사용하고, 없으면 로드해서 pin 한다
//   - AttachAll · AttachedHooks: LSM · tracepoint 훅을 붙이고 목록을 돌려준다
//   - BpfLsmEnabled: /sys/kernel/security/lsm 에 bpf 가 있는지 확인한다
//
// 부르는 쪽: cmd/warrantd 기동 1·3단계. 상태: 미구현 (지금은 bpftool 로 대신한다).
package loader

type Loader struct{}

// Load 는 이미 pin 된 맵이 있으면 새로 만들지 않고 재사용한다.
func Load(pinDir string) (*Loader, error) {
	panic("미구현")
}

func (l *Loader) AttachAll() error {
	panic("미구현")
}

func (l *Loader) AttachedHooks() []string {
	panic("미구현")
}

// Close 는 링크만 닫는다. pin 은 지우지 않는다.
func (l *Loader) Close() error {
	panic("미구현")
}

func BpfLsmEnabled() (bool, error) {
	panic("미구현")
}
