package main

import (
	"net"
	"os"
)

// Tells systemd (Type=notify) a state such as READY=1; a no-op when not started by systemd.
// READY is sent only after the PAM socket exists, so sshd (Before= in the unit) never sees a missing socket.
func sdNotify(state string) error {
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" {
		return nil
	}
	if addr[0] == '@' { // abstract namespace
		addr = "\x00" + addr[1:]
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: addr, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte(state))
	return err
}
