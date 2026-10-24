package main

import (
	"net"
	"path/filepath"
	"testing"
	"time"
)

// systemd 가 듣는 소켓을 흉내 낸다. Type=notify 는 이 한 줄을 받아야 sshd 를 시작한다.
func TestSdNotifySendsReadyToSystemd(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notify.sock")
	l, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	t.Setenv("NOTIFY_SOCKET", path)

	if err := sdNotify("READY=1"); err != nil {
		t.Fatal(err)
	}

	l.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, _, err := l.ReadFromUnix(buf)
	if err != nil {
		t.Fatalf("systemd got nothing: %v", err)
	}
	if got := string(buf[:n]); got != "READY=1" {
		t.Fatalf("systemd got %q, want READY=1", got)
	}
}

// systemd 밖(손으로 띄운 warrantd)에서는 아무 일도 하지 않는다.
func TestSdNotifyOutsideSystemdDoesNothing(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	if err := sdNotify("READY=1"); err != nil {
		t.Fatalf("sdNotify without NOTIFY_SOCKET: %v", err)
	}
}
