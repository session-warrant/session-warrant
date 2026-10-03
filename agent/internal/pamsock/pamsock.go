// Package pamsock 은 pam_warrant.so 가 보내는 세션 정보를 받는다.
//
// SOCK_DGRAM, 한 데이터그램에 한 줄. 응답은 없다 — PAM 은 기다리지 않는다.
//
//	OPEN\tsession_id\tcgroup_id\tlogin_account\trhost\tauth_info\n
//	CLOSE\tsession_id\tcgroup_id\n
//
// 값이 없으면 "-". 형식은 pam/pam_warrant.c 와 같이 고친다.
package pamsock

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

type Request struct {
	Op           string // OPEN · CLOSE
	SessionID    string // 숫자가 아닐 수 있다 (c1). 키로 쓰지 않는다
	CgroupID     uint64 // 바인딩 키. 0 이면 못 구했다
	LoginAccount string
	RHost        string
	AuthInfo     string // SSH_AUTH_INFO_0 원문. 여러 줄 · 끝 공백 가능
}

type Server struct {
	conn *net.UnixConn
}

func Listen(socketPath string) (*Server, error) {
	if err := os.Remove(socketPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("pamsock: remove %s: %w", socketPath, err)
	}

	la, err := net.ResolveUnixAddr("unixgram", socketPath)
	if err != nil {
		return nil, fmt.Errorf("pamsock: resolve %s: %w", socketPath, err)
	}

	conn, err := net.ListenUnixgram("unixgram", la)
	if err != nil {
		return nil, fmt.Errorf("pamsock: listen %s: %w", socketPath, err)
	}

	if err := os.Chmod(socketPath, 0o600); err != nil {
		conn.Close()
		return nil, fmt.Errorf("pamsock: chmod %s: %w", socketPath, err)
	}

	return &Server{conn: conn}, nil
}

func (s *Server) Serve(ctx context.Context, b Binder) error {
	stop := context.AfterFunc(ctx, func() { s.conn.Close() })
	defer stop()

	buf := make([]byte, 4096)
	for {
		n, err := s.conn.Read(buf)

		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}

		req, err := parse(buf[:n])
		if err != nil {
			log.Printf("%v", err)
			continue
		}

		switch req.Op {
		case "OPEN":
			if _, err := b.Bind(ctx, req); err != nil {
				log.Printf("pamsock: bind cgroup %d: %v", req.CgroupID, err)
				continue
			}

		case "CLOSE":
			if req.CgroupID == 0 {
				continue
			}
			if err := b.Unbind(ctx, req.CgroupID); err != nil {
				log.Printf("pamsock: unbind cgroup %d: %v", req.CgroupID, err)
				continue
			}

		}
	}

}

// Called by Serve for each datagram.
// Parses one datagram into a Request.
func parse(b []byte) (Request, error) {
	s := strings.TrimSuffix(string(b), "\n")

	op, rest, ok := strings.Cut(s, "\t")
	if !ok {
		return Request{}, fmt.Errorf("pamsock: no fields (%d bytes)", len(b))
	}

	switch op {
	case "OPEN":
		f := strings.SplitN(rest, "\t", 5)
		if len(f) != 5 {
			return Request{}, fmt.Errorf("pamsock: OPEN: want 5 fields, got %d", len(f))
		}
		cgid, err := parseCgroupID(f[1])
		if err != nil {
			return Request{}, err
		}
		return Request{
			Op:           op,
			SessionID:    orEmpty(f[0]),
			CgroupID:     cgid,
			LoginAccount: orEmpty(f[2]),
			RHost:        orEmpty(f[3]),
			AuthInfo:     orEmpty(f[4]),
		}, nil

	case "CLOSE":
		f := strings.Split(rest, "\t")
		if len(f) != 2 {
			return Request{}, fmt.Errorf("pamsock: CLOSE: want 2 fields, got %d", len(f))
		}
		cgid, err := parseCgroupID(f[1])
		if err != nil {
			return Request{}, err
		}
		return Request{Op: op, SessionID: orEmpty(f[0]), CgroupID: cgid}, nil

	default:
		return Request{}, fmt.Errorf("pamsock: unknown op %q", op)
	}
}

// Called by parse.
// Reads cgroup_id; "-" returns 0.
func parseCgroupID(v string) (uint64, error) {
	if v == "-" {
		return 0, nil
	}
	id, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("pamsock: cgroup_id: %w", err)
	}
	return id, nil
}

func orEmpty(v string) string {
	if v == "-" {
		return ""
	}
	return v
}

// Implement at cmd/warrantd
type Binder interface {
	Bind(ctx context.Context, r Request) (warrantID uint64, err error)
	Unbind(ctx context.Context, cgroupID uint64) error
}

// Called by the Binder in cmd/warrantd.
// Returns "SHA256:..." of the publickey line's key (inner key for certs), or "" if none.
func Fingerprint(authInfo string) (string, error) {
	for _, line := range strings.Split(authInfo, "\n") {
		key, ok := strings.CutPrefix(line, "publickey ")
		if !ok {
			continue
		}
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key))
		if err != nil {
			return "", fmt.Errorf("pamsock: fingerprint: %w", err)
		}
		if cert, ok := pub.(*ssh.Certificate); ok {
			pub = cert.Key //인증서 방식
			// !ok 일 경우 일반키 방식
		}
		return ssh.FingerprintSHA256(pub), nil
	}
	return "", nil
}
