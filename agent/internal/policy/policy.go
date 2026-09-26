// Package policy 는 경로를 (dev, ino) 로 컴파일한다. 이 변환은 여기서만 한다.
package policy

import "github.com/session-warrant/session-warrant/agent/internal/bpfmap"

type Compiled struct {
	PolicyID uint32
	Exec     []bpfmap.FileRef
	Write    []WriteEntry
	Net      []NetEntry
	Read     []bpfmap.FileRef // 비어 있으면 BPF 가 읽기 경로를 아예 보지 않는다
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

// Compile 은 금지 규칙이 파일 inode 로 컴파일되면 거부한다. 금지는 디렉터리여야 한다.
func Compile(policyID uint32, spec any) (*Compiled, error) {
	panic("미구현")
}

// Watcher 는 inode 가 바뀌면 다시 컴파일한다. 놓치면 정책이 조용히 무효가 된다 (S4).
type Watcher struct{}

func NewWatcher() (*Watcher, error)                       { panic("미구현") }
func (w *Watcher) Watch(c *Compiled) error                { panic("미구현") }
func (w *Watcher) OnChange(f func(policyID uint32)) error { panic("미구현") }
func (w *Watcher) Close() error                           { panic("미구현") }
