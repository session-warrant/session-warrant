package bpfmap

import (
	"testing"
	"unsafe"
)

// 커널 구조체와 크기가 어긋나면 맵 조회가 에러 없이 빗나간다.
// 숫자는 bpf/warrant.bpf.h 의 _Static_assert 와 같아야 한다.
func TestLayoutSizes(t *testing.T) {
	cases := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"struct warrant", unsafe.Sizeof(Warrant{}), 32},
		{"warrant_rule_key", unsafe.Sizeof(ruleKey{}), 16},
		{"warrant_write_val", unsafe.Sizeof(writeVal{}), 8},
		{"warrant_net_key", unsafe.Sizeof(netKey{}), 24},
		{"warrant_net_val", unsafe.Sizeof(netVal{}), 16},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s: %d바이트, bpf/warrant.bpf.h 는 %d바이트", c.name, c.got, c.want)
		}
	}
}

// 필드 오프셋까지 봐야 한다 — 크기가 같아도 패딩 자리가 다르면 값이 밀린다.
func TestWarrantOffsets(t *testing.T) {
	var w Warrant
	cases := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"expires_ns", unsafe.Offsetof(w.ExpiresNs), 0},
		{"grace_ns", unsafe.Offsetof(w.GraceNs), 8},
		{"subject_id", unsafe.Offsetof(w.SubjectID), 16},
		{"policy_id", unsafe.Offsetof(w.PolicyID), 20},
		{"revoked", unsafe.Offsetof(w.Revoked), 24},
		{"mode", unsafe.Offsetof(w.Mode), 25},
		{"on_expiry", unsafe.Offsetof(w.OnExpiry), 26},
		{"break_glass", unsafe.Offsetof(w.BreakGlass), 27},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("Warrant.%s 오프셋 %d, 커널은 %d", c.name, c.got, c.want)
		}
	}
}
