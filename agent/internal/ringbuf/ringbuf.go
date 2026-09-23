// Package ringbuf 는 커널 events ringbuf 를 소비해 감사 이벤트로 바꾼다.
//
// A(커널) 소유. 유실을 숨기지 않는 것이 이 패키지의 존재 이유다(§13, §14).
package ringbuf

import "context"

// Record 는 커널이 찍은 레코드 한 건이다. 필드 구성은 proto/audit.proto 의 AuditEvent 와
// 1:1 이지만, proto 메시지로 바꾸는 것은 upstream 의 일이다.
type Record struct {
	CPU        uint32
	CPUSeq     uint64 // (cpu, cpu_seq) 가 건너뛰면 유실이다
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

// Consumer 는 ringbuf 를 읽어 handler 로 넘긴다.
type Consumer struct{}

// Open 은 pin 된 ringbuf 를 연다.
func Open(pinDir string) (*Consumer, error) {
	panic("미구현")
}

// Run 은 ctx 가 끝날 때까지 소비한다. handler 가 느리면 커널이 드롭하므로
// handler 안에서 네트워크를 기다리지 말 것 — store 에 넣고 바로 돌아온다.
func (c *Consumer) Run(ctx context.Context, handler func(Record)) error {
	panic("미구현")
}

// DroppedTotal 은 부팅 이후 누적 드롭 수다. HeartbeatRequest 로 올라간다.
func (c *Consumer) DroppedTotal() uint64 {
	panic("미구현")
}

// Gap 은 유실 구간이다. cpu_seq 가 건너뛴 것을 보고 만든다.
// 빈 구간을 숨기면 조사자가 "이 시간대에는 아무 일도 없었다"로 잘못 읽는다.
type Gap struct {
	FromUnixNs   uint64
	ToUnixNs     uint64
	DroppedCount uint64
	Known        bool
	Cause        string // RINGBUF_OVERFLOW · AGENT_DOWN · LOCAL_STORE_FULL · CPU_SEQ_SKIP
}
