package bpfmap

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// symlink 를 따라가지 않으면 /bin/sh 같은 경로에서 symlink 자신의 inode 가 잡힌다.
// 커널은 exec 할 때 대상을 열기 때문에 그 규칙은 영영 매칭되지 않는다.
// 에러가 안 나고 조용히 빗나가므로 여기서 고정한다.
func TestFileRefOfFollowsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")

	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	rt, err := FileRefOf(target)
	if err != nil {
		t.Fatal(err)
	}
	rl, err := FileRefOf(link)
	if err != nil {
		t.Fatal(err)
	}
	if rt != rl {
		t.Errorf("symlink 를 안 따라갔다: target=%+v link=%+v", rt, rl)
	}

	var lst unix.Stat_t
	if err := unix.Lstat(link, &lst); err != nil {
		t.Fatal(err)
	}
	if rl.Ino == lst.Ino {
		t.Error("symlink 자신의 inode 를 잡았다")
	}
}

// 커널 s_dev 는 12bit major : 20bit minor 다. 유저 공간 st_dev 인코딩과 다르다.
func TestFileRefOfDevEncoding(t *testing.T) {
	f := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	ref, err := FileRefOf(f)
	if err != nil {
		t.Fatal(err)
	}

	var st unix.Stat_t
	if err := unix.Stat(f, &st); err != nil {
		t.Fatal(err)
	}
	want := uint32(unix.Major(uint64(st.Dev))<<20 | unix.Minor(uint64(st.Dev)))
	if ref.Dev != want {
		t.Errorf("dev=%d, 커널 인코딩은 %d", ref.Dev, want)
	}
}

func TestNetKeyOf(t *testing.T) {
	const policy = 0x01020304

	cases := []struct {
		cidr      string
		prefixLen uint32
		addr      []byte // Addr 의 앞부분만 확인
		at        int
	}{
		// IPv4 는 ::ffff:a.b.c.d 로 펴진다. 앞 96비트가 고정이라 프리픽스에 들어간다.
		{"10.0.0.0/8", 32 + 96 + 8, []byte{0xff, 0xff, 10, 0, 0, 0}, 10},
		{"192.168.1.5/32", 32 + 96 + 32, []byte{0xff, 0xff, 192, 168, 1, 5}, 10},
		{"0.0.0.0/0", 32 + 96 + 0, []byte{0xff, 0xff, 0, 0, 0, 0}, 10},
		// IPv6 는 그대로 들어간다.
		{"2001:db8::/32", 32 + 32, []byte{0x20, 0x01, 0x0d, 0xb8}, 0},
	}

	for _, c := range cases {
		k, err := netKeyOf(policy, c.cidr)
		if err != nil {
			t.Fatalf("%s: %v", c.cidr, err)
		}
		if k.PrefixLen != c.prefixLen {
			t.Errorf("%s: prefixlen=%d, 기대 %d", c.cidr, k.PrefixLen, c.prefixLen)
		}
		for i, b := range c.addr {
			if k.Addr[c.at+i] != b {
				t.Errorf("%s: Addr[%d]=%#x, 기대 %#x", c.cidr, c.at+i, k.Addr[c.at+i], b)
			}
		}
	}
}

// LPM trie 는 MSB 부터 맞춘다. policy_id 를 host order 로 넣으면 엉뚱한 정책에 걸린다.
func TestNetKeyPolicyIDIsBigEndian(t *testing.T) {
	k, err := netKeyOf(0x01020304, "10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	// 메모리에 04 03 02 01 순으로 놓여야 하고, little-endian 기계에서 그건 0x04030201 이다.
	if k.PolicyIDBE != 0x04030201 {
		t.Errorf("PolicyIDBE=%#x, 기대 %#x", k.PolicyIDBE, 0x04030201)
	}
}

func TestNetKeyOfRejectsBadCIDR(t *testing.T) {
	for _, s := range []string{"10.0.0.1", "not-a-cidr", "10.0.0.0/99", ""} {
		if _, err := netKeyOf(1, s); err == nil {
			t.Errorf("%q 를 받아들였다", s)
		}
	}
}

func TestPortIndex(t *testing.T) {
	v := netVal{NPorts: 3, Ports: [7]uint16{22, 443, 8080}}
	if portIndex(v, 443) != 1 {
		t.Error("있는 포트를 못 찾았다")
	}
	if portIndex(v, 9999) != -1 {
		t.Error("없는 포트를 찾았다고 한다")
	}
	// NPorts 를 넘는 자리에 쓰레기가 있어도 보면 안 된다.
	v2 := netVal{NPorts: 1, Ports: [7]uint16{22, 443}}
	if portIndex(v2, 443) != -1 {
		t.Error("NPorts 밖을 봤다")
	}
}
