// Package policy 는 사람이 읽는 정책을 커널이 아는 (dev, ino) 로 컴파일한다.
//
// A(커널) 소유. 이 변환은 여기서만 한다 — 중앙은 경로 문자열만 알고 커널은 inode 만 안다.
package policy

import "github.com/session-warrant/session-warrant/agent/internal/bpfmap"

// Compiled 는 한 정책 버전의 컴파일 결과다.
type Compiled struct {
	PolicyID uint32 // 불변 정책 버전 id. 같은 id 에 다른 내용이 오면 Compile 전에 거부한다
	Exec     []bpfmap.FileRef
	Write    []WriteEntry
	Net      []NetEntry
	Read     []bpfmap.FileRef // read_watch_paths. 비어 있으면 BPF 가 읽기 경로를 아예 보지 않는다
}

type WriteEntry struct {
	Ref       bpfmap.FileRef
	Allow     bool
	Recursive bool
}

type NetEntry struct {
	CIDR  string
	Port  uint16
	Proto uint8
}

// Compile 은 경로를 stat 해서 (dev, ino) 로 바꾼다.
//
// 금지 규칙이 파일 inode 로 컴파일되면 거부한다 — 반드시 디렉터리 inode 여야 한다.
// 파일 inode 금지는 mv 후 재생성으로 뚫린다(§15).
func Compile(policyID uint32, spec any) (*Compiled, error) {
	panic("미구현")
}

// Watcher 는 fanotify 로 컴파일된 경로를 감시하다가 inode 가 바뀌면 다시 컴파일한다.
//
// 어느 조작이 inode 를 바꾸고 fanotify 가 그걸 잡는지는 S4(bench/inode)가 잰다.
// 놓치면 정책이 조용히 무효가 된다 — 에러도 로그도 없이.
type Watcher struct{}

func NewWatcher() (*Watcher, error)                       { panic("미구현") }
func (w *Watcher) Watch(c *Compiled) error                { panic("미구현") }
func (w *Watcher) OnChange(f func(policyID uint32)) error { panic("미구현") }
func (w *Watcher) Close() error                           { panic("미구현") }
