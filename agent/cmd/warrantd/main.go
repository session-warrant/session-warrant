// warrantd — 노드 에이전트.
//
// C(노드 통합) 소유. 이 파일이 하는 일은 조립뿐이다 — 판정은 커널이 혼자 한다.
//
// # 기동 순서 (바꾸지 말 것)
//
//  1. loader.Load — 맵이 bpffs 에 pin 돼 있으면 그것을 재사용한다
//  2. store.Open  — 캐시된 영장을 맵에 복원. 중앙이 안 떠 있어도 집행은 이어진다
//  3. loader.AttachAll
//  4. pamsock.Listen — 여기까지 오기 전에 세션이 생기면 태깅 공백이다.
//     systemd 유닛에 Before=sshd.service 가 필수인 이유다
//  5. ringbuf.Run · upstream.Subscribe — 중앙 연결은 마지막. 실패해도 계속 뜬다
//
// # 종료
//
// 링크만 닫고 pin 은 지우지 않는다. 지우면 다음 기동까지 태그가 사라진다.
package main

import (
	"flag"
	"log"
)

func main() {
	var (
		pinDir     = flag.String("pin-dir", "/sys/fs/bpf/warrant", "bpffs pin 경로")
		socketPath = flag.String("pam-socket", "/run/warrantd/pam.sock", "pam_warrant.so 가 붙는 소켓")
		statePath  = flag.String("state", "/var/lib/warrantd/state.db", "bbolt 경로")
		upstreamEP = flag.String("upstream", "", "중앙 gRPC 엔드포인트. 비어 있으면 로컬 전용으로 뜬다")
	)
	flag.Parse()

	_ = pinDir
	_ = socketPath
	_ = statePath
	_ = upstreamEP

	// 1~5 조립. 중앙 연결 실패는 치명이 아니다 —
	// 이미 발급된 영장의 집행은 중앙이 끊겨도 계속된다(§10, §17).
	log.Fatal("미구현")
}
