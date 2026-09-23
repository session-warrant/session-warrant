// Package pamsock 은 pam_warrant.so 가 보내는 세션 정보를 받아 cgroup 을 태깅한다.
//
// C(노드 통합) 소유. 소켓 양 끝(pam/ 과 이 패키지)을 같은 사람이 쓰므로
// 와이어 포맷을 문서로 합의할 필요가 없다 — protobuf 도 쓰지 않는다.
//
// # 와이어 포맷 (초안, pam/ 과 함께 확정한다)
//
// 줄 단위 텍스트. PAM 쪽이 200줄 제한이라 파서를 단순하게 둔다.
//
//	OPEN\tsession_id\tcgroup_id\tlogin_account\trhost\tauth_info\n
//	CLOSE\tsession_id\tcgroup_id\n
//
// 응답은 "OK\n" 또는 "NOWARRANT\n". PAM 은 어느 쪽이든 로그인을 허용한다 —
// 여기서 fail-close 를 택하면 장애 때 아무도 못 들어간다(§17).
//
// # 왜 PAM 이 cgroup id 를 계산해 보내나
//
// S3 에서 session 단계 진입 시점에 session-N.scope 가 이미 확정돼 있음을 확인했다
// (present_t0 11/11 · waited_us=0). PAM 은 XDG_SESSION_ID 로 경로를 조립해 stat 하면 끝이다.
// XDG_SESSION_ID 는 재사용되지만 cgroup id 는 재사용되지 않는다 —
// 영장을 세션 번호에 걸면 다음 세션이 남의 영장을 물려받는다.
package pamsock

import "context"

// Request 는 PAM 한 줄이다.
type Request struct {
	Op           string // OPEN · CLOSE
	SessionID    string // XDG_SESSION_ID. 재사용되므로 키로 쓰지 않는다
	CgroupID     uint64 // 바인딩 키
	LoginAccount string
	RHost        string // PAM_RHOST
	AuthInfo     string // SSH_AUTH_INFO_0 원문. 지문 계산은 여기(Go)서 한다
}

// Server 는 유닉스 소켓을 듣는다. 소켓 권한은 0600 · root 소유 —
// 아무나 쓸 수 있으면 임의 cgroup 태깅이 된다.
type Server struct{}

func Listen(socketPath string) (*Server, error) {
	panic("미구현")
}

// Serve 는 요청을 받아 binder 로 넘긴다. sshd 의 PAM 스택 안에서 기다리는 호출이므로
// 여기서 중앙을 동기로 기다리지 않는다 — warrantd 캐시가 답하고, 캐시가 비었을 때만
// 짧은 타임아웃으로 LookupActiveWarrant 를 부른다.
func (s *Server) Serve(ctx context.Context, b Binder) error {
	panic("미구현")
}

// Binder 는 세션을 영장에 잇는다. 구현은 cmd/warrantd 가 조립한다.
type Binder interface {
	// Bind 는 (hostname, login_account, ssh 공개키 지문) 셋이 다 맞는 영장을 찾아
	// cgroup 을 태깅한다. 못 찾으면 무영장으로 기록하고 nil 을 돌려준다(로그인은 허용).
	Bind(ctx context.Context, r Request) (warrantID uint64, err error)

	// Unbind 는 close_session 에서 cgroup 태그를 지운다.
	Unbind(ctx context.Context, cgroupID uint64) error
}

// Fingerprint 는 SSH_AUTH_INFO_0 한 줄에서 "SHA256:..." 지문을 뽑는다.
//
//	publickey ssh-ed25519 AAAA...
//
// AuthenticationMethods 로 여러 방식을 거쳤으면 여러 줄이다 — publickey 줄을 쓴다.
// 인증서(*-cert-v01@openssh.com)면 인증서 안의 공개키 지문을 쓴다.
// 형식은 ssh-keygen -lf 출력과 같아야 한다 — 사람이 눈으로 대조할 수 있어야 한다.
//
// 빈 문자열이면 공개키 인증이 아니다(REASON_NO_KEY). 와일드카드가 아니라 "매칭 안 함"이다.
func Fingerprint(authInfo string) (string, error) {
	panic("미구현")
}
