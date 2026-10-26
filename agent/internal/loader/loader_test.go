package loader

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
)

func TestHasBPF(t *testing.T) {
	cases := []struct {
		list string
		want bool
	}{
		{"lockdown,capability,landlock,yama,apparmor,bpf", true},
		{"capability,apparmor,bpf\n", true},
		{"bpf", true},
		{" bpf , apparmor ", true},
		{"lockdown,capability,landlock,yama,apparmor", false},
		{"", false},
		// bpf 가 다른 이름의 일부일 뿐인 경우를 허용으로 읽으면 안 된다.
		{"capability,bpfoo", false},
		{"mybpf,apparmor", false},
	}
	for _, c := range cases {
		if got := hasBPF(c.list); got != c.want {
			t.Errorf("hasBPF(%q) = %v, 기대 %v", c.list, got, c.want)
		}
	}
}

func TestBpfLsmEnabled(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "lsm")

	orig := lsmPath
	lsmPath = p
	defer func() { lsmPath = orig }()

	if err := os.WriteFile(p, []byte("capability,apparmor,bpf\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	on, err := BpfLsmEnabled()
	if err != nil {
		t.Fatal(err)
	}
	if !on {
		t.Error("bpf 가 목록에 있는데 꺼졌다고 했다")
	}

	if err := os.WriteFile(p, []byte("capability,apparmor\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if on, _ := BpfLsmEnabled(); on {
		t.Error("bpf 가 없는데 켜졌다고 했다")
	}

	// 파일 자체가 없으면 「꺼짐」이 아니라 에러여야 한다 —
	// securityfs 가 안 올라온 것과 bpf LSM 이 꺼진 것은 다른 상황이다.
	lsmPath = filepath.Join(dir, "없는파일")
	if _, err := BpfLsmEnabled(); err == nil {
		t.Error("파일이 없는데 에러가 안 났다")
	}
}

func TestKprobeSymbol(t *testing.T) {
	cases := []struct {
		attachTo string
		section  string
		want     string
	}{
		{"security_file_open", "kprobe/security_file_open", "security_file_open"},
		{"", "kprobe/security_file_open", "security_file_open"},
		{"", "kprobe", ""},
		{"", "", ""},
	}
	for _, c := range cases {
		got := kprobeSymbol(&ebpf.ProgramSpec{AttachTo: c.attachTo, SectionName: c.section})
		if got != c.want {
			t.Errorf("AttachTo=%q SEC=%q → %q, 기대 %q", c.attachTo, c.section, got, c.want)
		}
	}
}

// 붙이는 방법을 모르는 종류는 조용히 넘어가면 안 된다.
// 훅 하나가 안 붙은 채로 도는 게 제일 위험하다.
func TestAttachByTypeRejectsUnknown(t *testing.T) {
	_, err := attachByType(nil, &ebpf.ProgramSpec{
		Type:        ebpf.SocketFilter,
		SectionName: "socket/whatever",
	})
	if err == nil {
		t.Error("모르는 종류를 받아들였다")
	}
}
