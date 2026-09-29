package ringbuf

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// 커널이 보내는 바이트를 그대로 만들어 넣고 풀어본다.
// 레이아웃이 어긋나면 값이 한 칸씩 밀리므로 필드값까지 확인한다.
func build(t *testing.T, h evtHeader, payload any) []byte {
	t.Helper()
	var buf bytes.Buffer
	if payload != nil {
		h.PayloadLen = uint16(binary.Size(payload))
	}
	if err := binary.Write(&buf, binary.LittleEndian, h); err != nil {
		t.Fatal(err)
	}
	if payload != nil {
		if err := binary.Write(&buf, binary.LittleEndian, payload); err != nil {
			t.Fatal(err)
		}
	}
	// 커널은 항상 최대 크기로 예약한다 — 뒤에 쓰레기가 붙어 와도 무시해야 한다.
	buf.Write(make([]byte, 40-buf.Len()+headerSize+binary.Size(payload)))
	return buf.Bytes()
}

func TestDecodeExec(t *testing.T) {
	h := evtHeader{
		CPUSeq: 42, BootTsNs: 1234567890, WarrantID: 7,
		CPU: 3, SubjectID: 99, PolicyID: 11,
		Hook: HookBprmCheckSecurity, Verdict: 1, Mode: 2, Origin: 1, TagSource: 2,
	}
	h.Proc = proc{
		PID: 1000, TGID: 1000, PPID: 999, UID: 1001, EUID: 0, GID: 1001,
		StartTimeNs: 5555, CgroupID: 8888,
	}
	copy(h.Proc.Comm[:], "bash\x00")

	pl := plExec{File: fileRef{Dev: 0x800002, Ino: 1311362}, IMode: 0o4755, NewUID: 0, NewEUID: 0}

	r, err := decode(build(t, h, pl))
	if err != nil {
		t.Fatal(err)
	}

	if r.CPUSeq != 42 || r.CPU != 3 || r.WarrantID != 7 || r.PolicyID != 11 {
		t.Errorf("머리 값이 밀렸다: %+v", r)
	}
	if r.Hook != HookBprmCheckSecurity || r.Verdict != 1 || r.Mode != 2 || r.TagSource != 2 {
		t.Errorf("판정 필드가 밀렸다: hook=%d verdict=%d mode=%d tag=%d",
			r.Hook, r.Verdict, r.Mode, r.TagSource)
	}
	if r.Proc.Comm != "bash" {
		t.Errorf("comm=%q", r.Proc.Comm)
	}
	if r.Proc.PID != 1000 || r.Proc.PPID != 999 || r.Proc.UID != 1001 || r.Proc.CgroupID != 8888 {
		t.Errorf("프로세스 필드가 밀렸다: %+v", r.Proc)
	}

	e, ok := r.Exec()
	if !ok {
		t.Fatal("Exec() 가 안 풀렸다")
	}
	if e.File.Dev != 0x800002 || e.File.Ino != 1311362 || e.IMode != 0o4755 {
		t.Errorf("payload 가 밀렸다: %+v", e)
	}

	// 훅이 다르면 다른 payload 로 풀리면 안 된다.
	if _, ok := r.Write(); ok {
		t.Error("exec 레코드가 Write() 로 풀렸다")
	}
}

func TestDecodeConnectIPv4IsUnmapped(t *testing.T) {
	// 커널은 IPv4 를 ::ffff:a.b.c.d 로 펴서 보낸다. 소비자는 10.2.0.5 로 봐야 한다.
	h := evtHeader{Hook: HookSocketConnect, CPUSeq: 1}
	pl := plConnect{Family: 2, Proto: 1, Port: 443}
	pl.Addr[10], pl.Addr[11] = 0xff, 0xff
	copy(pl.Addr[12:], []byte{10, 2, 0, 5})

	r, err := decode(build(t, h, pl))
	if err != nil {
		t.Fatal(err)
	}
	c, ok := r.Connect()
	if !ok {
		t.Fatal("Connect() 가 안 풀렸다")
	}
	if got := c.Addr.String(); got != "10.2.0.5" {
		t.Errorf("addr=%s, 기대 10.2.0.5", got)
	}
	if c.Port != 443 {
		t.Errorf("port=%d", c.Port)
	}
}

func TestDecodeConnectUnixPath(t *testing.T) {
	h := evtHeader{Hook: HookSocketConnect, CPUSeq: 1}
	pl := plConnect{Family: 1}
	copy(pl.Addr[:], "/run/dbus/system\x00")

	r, err := decode(build(t, h, pl))
	if err != nil {
		t.Fatal(err)
	}
	c, _ := r.Connect()
	if c.UnixPath != "/run/dbus/system" {
		t.Errorf("unix path=%q", c.UnixPath)
	}
	if c.Addr.IsValid() {
		t.Error("AF_UNIX 인데 IP 주소가 잡혔다")
	}
}

func TestDecodeRejectsShortRecord(t *testing.T) {
	if _, err := decode(make([]byte, headerSize-1)); err == nil {
		t.Error("짧은 레코드를 받아들였다")
	}
	// payload_len 이 실제 길이보다 크면 거부해야 한다 — 남의 메모리를 읽으면 안 된다.
	var h evtHeader
	h.PayloadLen = 200
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, h)
	if _, err := decode(buf.Bytes()); err == nil {
		t.Error("payload_len 이 넘치는 레코드를 받아들였다")
	}
}

// 커널이 reserve 전에 번호를 올리므로 빠진 번호가 곧 버려진 이벤트다.
func TestGapDetection(t *testing.T) {
	c := &Consumer{next: make(map[uint32]uint64)}
	var gaps []Gap
	c.OnGap(func(g Gap) { gaps = append(gaps, g) })

	c.checkGap(Record{CPU: 0, CPUSeq: 10}) // 첫 레코드 — 기준만 잡는다
	c.checkGap(Record{CPU: 0, CPUSeq: 11}) // 연속
	c.checkGap(Record{CPU: 0, CPUSeq: 15}) // 12·13·14 유실
	c.checkGap(Record{CPU: 1, CPUSeq: 99}) // 다른 CPU 는 따로 센다

	if len(gaps) != 1 {
		t.Fatalf("gap %d건, 기대 1건: %+v", len(gaps), gaps)
	}
	if gaps[0].DroppedCount != 3 || gaps[0].Cause != "CPU_SEQ_SKIP" {
		t.Errorf("%+v", gaps[0])
	}
	if c.DroppedTotal() != 3 {
		t.Errorf("누적 유실 %d, 기대 3", c.DroppedTotal())
	}
}

func TestGapIgnoresRestart(t *testing.T) {
	c := &Consumer{next: make(map[uint32]uint64)}
	c.checkGap(Record{CPU: 0, CPUSeq: 100})
	c.checkGap(Record{CPU: 0, CPUSeq: 3}) // 번호가 되돌아갔다 — 유실로 세지 않는다
	if c.DroppedTotal() != 0 {
		t.Errorf("되돌아간 번호를 유실로 셌다: %d", c.DroppedTotal())
	}
}
