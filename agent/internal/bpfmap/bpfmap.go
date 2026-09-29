// Package bpfmap 은 BPF 맵의 유일한 진입점이다. 다른 패키지는 맵을 직접 열지 않는다.
package bpfmap

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// proto/warrant.proto enum Mode 와 값이 같다.
const (
	ModeObserve uint8 = 0
	ModeDryRun  uint8 = 1
	ModeEnforce uint8 = 2
)

// proto/warrant.proto enum OnExpiry 와 값이 같다.
const (
	OnExpiryDemote           uint8 = 0
	OnExpiryKill             uint8 = 1
	OnExpirySessionOnlyGrace uint8 = 2
)

// proto/warrant.proto enum Proto 와 값이 같다.
const (
	ProtoAny uint8 = 0
	ProtoTCP uint8 = 1
	ProtoUDP uint8 = 2
)

// Warrant 는 warrants 맵의 값. bpf/warrant.bpf.h 의 struct warrant 와 바이트 단위로 같아야 한다.
// 필드는 proto/warrant.proto 를 먼저 고친다.
type Warrant struct {
	ExpiresNs  uint64 // boot 기준
	GraceNs    uint64
	SubjectID  uint32
	PolicyID   uint32
	Revoked    uint8
	Mode       uint8
	OnExpiry   uint8
	BreakGlass uint8   // 자기보호 5종을 통과하는 유일한 영장. 일반 발급 경로로는 못 켠다
	_          [4]byte // C 구조체와 크기를 맞추는 패딩
}

// FileRef 는 rule_* 키의 뒷부분. inode 번호는 파일시스템 안에서만 유일하므로 dev 를 빼면 안 된다.
type FileRef struct {
	Dev uint32
	Ino uint64
}

// FileRefOf 는 경로를 커널이 쓰는 (dev, ino) 로 바꾼다.
//
// 두 가지가 숨어 있고 둘 다 틀려도 에러가 안 난다 — 조회만 조용히 빗나간다.
//
//   - unix.Stat 은 symlink 를 따라간다. 커널도 exec 할 때 대상을 열므로 이게 맞다.
//     따라가지 않으면 /bin/sh 같은 경로에서 symlink 자신의 inode 가 잡힌다.
//   - 유저 공간 st_dev 는 glibc 인코딩이고 커널 s_dev 는 12bit major : 20bit minor 다.
//     그대로 넘기면 절대 매칭되지 않는다.
func FileRefOf(path string) (FileRef, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return FileRef{}, fmt.Errorf("stat %s: %w", path, err)
	}
	major := unix.Major(uint64(st.Dev))
	minor := unix.Minor(uint64(st.Dev))
	return FileRef{
		Dev: uint32(major<<20 | minor),
		Ino: st.Ino,
	}, nil
}

// BootNs 는 커널 bpf_ktime_get_boot_ns() 와 같은 시계를 읽는다.
//
// 절대시각 → boot 기준 변환에 쓴다. time.Now() 는 벽시계라 값이 완전히 다르고
// NTP 조정에도 흔들린다. 변환 자체는 warrantd 가 한 곳에서만 한다 (agent/README).
func BootNs() (uint64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return 0, fmt.Errorf("clock_gettime(CLOCK_BOOTTIME): %w", err)
	}
	return uint64(ts.Sec)*1e9 + uint64(ts.Nsec), nil
}

type Maps struct {
	activeFlag    *ebpf.Map
	cgroupWarrant *ebpf.Map
	warrants      *ebpf.Map
	ruleExec      *ebpf.Map
	ruleWrite     *ebpf.Map
	ruleNet       *ebpf.Map

	ncpu int
}

// Open 은 bpffs 에 pin 된 맵을 연다. 맵을 만들지는 않는다 — 그건 loader 몫이다.
func Open(pinDir string) (*Maps, error) {
	m := &Maps{}
	for _, p := range []struct {
		dst  **ebpf.Map
		name string
	}{
		{&m.activeFlag, "active_flag"},
		{&m.cgroupWarrant, "cgroup_warrant"},
		{&m.warrants, "warrants"},
		{&m.ruleExec, "rule_exec"},
		{&m.ruleWrite, "rule_write"},
		{&m.ruleNet, "rule_net"},
	} {
		mp, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, p.name), nil)
		if err != nil {
			_ = m.Close()
			return nil, fmt.Errorf("pin 된 맵 %s: %w", p.name, err)
		}
		*p.dst = mp
	}

	n, err := ebpf.PossibleCPU()
	if err != nil {
		_ = m.Close()
		return nil, err
	}
	m.ncpu = n
	return m, nil
}

// Close 는 열어둔 맵 핸들만 닫는다. pin 은 지우지 않는다.
func (m *Maps) Close() error {
	var errs []error
	for _, mp := range []*ebpf.Map{
		m.activeFlag, m.cgroupWarrant, m.warrants,
		m.ruleExec, m.ruleWrite, m.ruleNet,
	} {
		if mp != nil {
			errs = append(errs, mp.Close())
		}
	}
	return errors.Join(errs...)
}

// PutWarrant 의 w.ExpiresNs 는 이미 boot 기준으로 변환된 값이어야 한다.
func (m *Maps) PutWarrant(id uint64, w Warrant) error {
	if err := m.warrants.Put(id, w); err != nil {
		return fmt.Errorf("영장 %d 쓰기: %w", id, err)
	}
	return nil
}

// Revoke 는 revoked 한 바이트만 뒤집는다.
func (m *Maps) Revoke(id uint64) error {
	var w Warrant
	if err := m.warrants.Lookup(id, &w); err != nil {
		return fmt.Errorf("영장 %d 조회: %w", id, err)
	}
	w.Revoked = 1
	if err := m.warrants.Put(id, w); err != nil {
		return fmt.Errorf("영장 %d 취소: %w", id, err)
	}
	return nil
}

func (m *Maps) DeleteWarrant(id uint64) error {
	return ignoreMissing(m.warrants.Delete(id))
}

func (m *Maps) TagCgroup(cgroupID, warrantID uint64) error {
	if err := m.cgroupWarrant.Put(cgroupID, warrantID); err != nil {
		return fmt.Errorf("cgroup %d 태그: %w", cgroupID, err)
	}
	return nil
}

// UntagCgroup 은 세션이 끝날 때 1차 태그를 지운다.
// fork 로 퍼진 2차 태그는 남는다 — 그건 프로세스가 죽어야 사라진다.
func (m *Maps) UntagCgroup(cgroupID uint64) error {
	return ignoreMissing(m.cgroupWarrant.Delete(cgroupID))
}

func (m *Maps) PutExecRule(policyID uint32, f FileRef) error {
	k := ruleKey{PolicyID: policyID, Dev: f.Dev, Ino: f.Ino}
	if err := m.ruleExec.Put(k, uint8(1)); err != nil {
		return fmt.Errorf("실행 규칙 (%d, %d): %w", f.Dev, f.Ino, err)
	}
	return nil
}

// PutWriteRule 의 allow=false 는 금지다. 금지는 반드시 디렉터리 inode 여야 한다 —
// 파일 inode 에 걸면 mv 후 재생성으로 뚫린다 (§15). 그 검사는 policy 가 한다.
//
// recursive=false 면 그 디렉터리의 직계 자식까지만 적용된다.
func (m *Maps) PutWriteRule(policyID uint32, f FileRef, allow bool, recursive bool) error {
	v := writeVal{Effect: EffectDeny}
	if allow {
		v.Effect = EffectAllow
	}
	if recursive {
		v.Recursive = 1
	}
	k := ruleKey{PolicyID: policyID, Dev: f.Dev, Ino: f.Ino}
	if err := m.ruleWrite.Put(k, v); err != nil {
		return fmt.Errorf("쓰기 규칙 (%d, %d): %w", f.Dev, f.Ino, err)
	}
	return nil
}

// MaxPortsPerRule 은 한 CIDR 에 담을 수 있는 포트 수다. 넘으면 대역을 쪼개야 한다.
const MaxPortsPerRule = 7

// PutNetRule 은 아웃바운드 허용 대역을 등록한다. port=0 이면 모든 포트다.
//
// IPv4 는 ::ffff:a.b.c.d 로 펴서 IPv6 와 같은 trie 에 넣는다. family 를 키에 따로
// 두지 않아도 주소 공간이 겹치지 않는다.
//
// 같은 CIDR 을 여러 번 부르면 포트를 합친다 — LPM trie 는 키 하나에 값 하나뿐이라
// 그냥 덮어쓰면 앞에 넣은 포트가 조용히 사라진다.
func (m *Maps) PutNetRule(policyID uint32, cidr string, port uint16, proto uint8) error {
	k, err := netKeyOf(policyID, cidr)
	if err != nil {
		return err
	}

	v := netVal{Proto: proto}
	var cur netVal
	found := false
	switch err := m.ruleNet.Lookup(k, &cur); {
	case err == nil:
		if cur.Proto != proto {
			// 같은 대역에 TCP 규칙과 UDP 규칙을 따로 둘 수 없다 — 값이 하나뿐이다.
			// policy 가 대역을 쪼개거나 ANY 로 올려야 한다.
			return fmt.Errorf("%s: 이미 proto=%d 로 등록돼 있다 (요청 proto=%d)",
				cidr, cur.Proto, proto)
		}
		v = cur
		found = true
	case isMissing(err):
		// 새 엔트리
	default:
		return fmt.Errorf("%s 조회: %w", cidr, err)
	}

	// NPorts=0 은 「모든 포트」다. 없는 값이 아니라 가장 넓은 값이므로 좁히지 않는다.
	// 그래서 기존 엔트리가 있었는지를 값으로 넘겨짚지 않고 found 로 가른다.
	switch {
	case port == 0:
		v.NPorts = 0 // 앞서 넣은 개별 포트는 의미가 없어진다
	case found && v.NPorts == 0:
		// 이미 모든 포트가 열려 있다. 그대로 둔다
	default:
		if portIndex(v, port) < 0 {
			if int(v.NPorts) >= MaxPortsPerRule {
				return fmt.Errorf("%s: 포트가 %d개를 넘는다. 대역을 쪼개야 한다",
					cidr, MaxPortsPerRule)
			}
			v.Ports[v.NPorts] = port
			v.NPorts++
		}
	}

	if err := m.ruleNet.Put(k, v); err != nil {
		return fmt.Errorf("네트워크 규칙 %s: %w", cidr, err)
	}
	return nil
}

// SetActive(false) 면 모든 훅이 즉시 통과한다.
func (m *Maps) SetActive(active bool) error {
	var b uint8
	if active {
		b = 1
	}
	vals := make([]uint8, m.ncpu)
	for i := range vals {
		vals[i] = b
	}
	if err := m.activeFlag.Put(uint32(0), vals); err != nil {
		return fmt.Errorf("active_flag: %w", err)
	}
	return nil
}

// ── 내부 ──────────────────────────────────────────────────────────

// netKeyOf 는 CIDR 을 LPM trie 키로 바꾼다.
// policy_id 는 big-endian 이어야 한다 — LPM 은 MSB 부터 맞춘다.
func netKeyOf(policyID uint32, cidr string) (netKey, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return netKey{}, fmt.Errorf("CIDR %s: %w", cidr, err)
	}
	ones, _ := ipnet.Mask.Size()

	var k netKey
	k.PolicyIDBE = swap32(policyID)

	if ip4 := ipnet.IP.To4(); ip4 != nil {
		// ::ffff:a.b.c.d — 앞 96비트는 고정이라 프리픽스 길이에 포함된다
		k.Addr[10], k.Addr[11] = 0xff, 0xff
		copy(k.Addr[12:], ip4)
		k.PrefixLen = 32 + 96 + uint32(ones)
	} else {
		copy(k.Addr[:], ipnet.IP.To16())
		k.PrefixLen = 32 + uint32(ones)
	}
	return k, nil
}

func swap32(v uint32) uint32 {
	return v>>24 | (v>>8)&0xff00 | (v<<8)&0xff0000 | v<<24
}

func portIndex(v netVal, port uint16) int {
	for i := 0; i < int(v.NPorts) && i < MaxPortsPerRule; i++ {
		if v.Ports[i] == port {
			return i
		}
	}
	return -1
}

func isMissing(err error) bool { return errors.Is(err, ebpf.ErrKeyNotExist) }

func ignoreMissing(err error) error {
	if isMissing(err) {
		return nil
	}
	return err
}
