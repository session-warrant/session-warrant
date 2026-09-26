// Package pamsock 은 pam_warrant.so 가 보내는 세션 정보를 받는다.
//
// SOCK_DGRAM, 한 데이터그램에 한 줄. 응답은 없다 — PAM 은 기다리지 않는다.
//
//	OPEN\tsession_id\tcgroup_id\tlogin_account\trhost\tauth_info\n
//	CLOSE\tsession_id\tcgroup_id\n
//
// 값이 없으면 "-". 형식은 pam/pam_warrant.c 와 같이 고친다.
package pamsock

import "context"

type Request struct {
	Op           string // OPEN · CLOSE
	SessionID    string // 숫자가 아닐 수 있다 (c1). 키로 쓰지 않는다
	CgroupID     uint64 // 바인딩 키. 0 이면 못 구했다
	LoginAccount string
	RHost        string
	AuthInfo     string // SSH_AUTH_INFO_0 원문. 여러 줄 · 끝 공백 가능
}

// Server 의 소켓은 root 전용(0600)이고, 보낸 쪽 uid 가 0 이 아니면 버린다.
// 공개키는 비밀이 아니라서 메시지 내용만으로는 위조를 막을 수 없다.
type Server struct{}

func Listen(socketPath string) (*Server, error) {
	panic("미구현")
}

// Serve 는 수신 큐를 빨리 비운다. 큐가 차면 PAM 쪽 sendto 가 조용히 실패한다.
func (s *Server) Serve(ctx context.Context, b Binder) error {
	panic("미구현")
}

// Binder 의 구현은 cmd/warrantd 가 조립한다.
type Binder interface {
	// Bind 는 (hostname, login_account, 공개키 지문) 셋이 다 맞는 영장에 잇는다.
	// 못 찾으면 무영장으로 기록할 뿐 에러가 아니다.
	Bind(ctx context.Context, r Request) (warrantID uint64, err error)
	Unbind(ctx context.Context, cgroupID uint64) error
}

// Fingerprint 는 publickey 줄에서 ssh-keygen -lf 와 같은 "SHA256:..." 를 만든다.
// 인증서면 안의 공개키 지문. 빈 값은 "매칭 안 함"이지 와일드카드가 아니다.
func Fingerprint(authInfo string) (string, error) {
	panic("미구현")
}
