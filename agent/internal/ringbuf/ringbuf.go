// Package ringbuf 는 커널 events ringbuf 를 소비한다. 유실은 Gap 으로 드러낸다.
package ringbuf

import "context"

type Record struct {
	CPU        uint32
	CPUSeq     uint64 // (cpu, cpu_seq) 가 건너뛰면 유실
	Hook       uint16
	Verdict    uint8
	Mode       uint8
	Origin     uint8
	TagSource  uint8
	BootTsNs   uint64
	WarrantID  uint64
	SubjectID  uint32
	PolicyID   uint32
	PayloadRaw []byte
}

type Consumer struct{}

func Open(pinDir string) (*Consumer, error) {
	panic("미구현")
}

// Run 의 handler 는 네트워크를 기다리지 않는다. 느리면 커널이 드롭한다.
func (c *Consumer) Run(ctx context.Context, handler func(Record)) error {
	panic("미구현")
}

func (c *Consumer) DroppedTotal() uint64 {
	panic("미구현")
}

type Gap struct {
	FromUnixNs   uint64
	ToUnixNs     uint64
	DroppedCount uint64
	Known        bool
	Cause        string // RINGBUF_OVERFLOW · AGENT_DOWN · LOCAL_STORE_FULL · CPU_SEQ_SKIP
}
