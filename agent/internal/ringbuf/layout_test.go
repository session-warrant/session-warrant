package ringbuf

import (
	"testing"
	"unsafe"
)

// 숫자는 bpf/warrant.bpf.h 의 _Static_assert 와 같아야 한다.
func TestLayoutSizes(t *testing.T) {
	cases := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"warrant_proc", unsafe.Sizeof(proc{}), 64},
		{"warrant_evt", unsafe.Sizeof(evtHeader{}), 112},
		{"warrant_fileref", unsafe.Sizeof(fileRef{}), 16},
		{"warrant_pl_exec", unsafe.Sizeof(plExec{}), 32},
		{"warrant_pl_write", unsafe.Sizeof(plWrite{}), 40},
		{"warrant_pl_inode", unsafe.Sizeof(plInode{}), 40},
		{"warrant_pl_connect", unsafe.Sizeof(plConnect{}), 24},
		{"warrant_pl_fork", unsafe.Sizeof(plFork{}), 16},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s: %d바이트, bpf/warrant.bpf.h 는 %d바이트", c.name, c.got, c.want)
		}
	}
}

func TestEvtHeaderOffsets(t *testing.T) {
	var e evtHeader
	cases := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"cpu_seq", unsafe.Offsetof(e.CPUSeq), 0},
		{"boot_ts_ns", unsafe.Offsetof(e.BootTsNs), 8},
		{"warrant_id", unsafe.Offsetof(e.WarrantID), 16},
		{"cpu", unsafe.Offsetof(e.CPU), 24},
		{"hook", unsafe.Offsetof(e.Hook), 36},
		{"payload_len", unsafe.Offsetof(e.PayloadLen), 42},
		{"proc", unsafe.Offsetof(e.Proc), 48},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("evtHeader.%s 오프셋 %d, 커널은 %d", c.name, c.got, c.want)
		}
	}
}
