// warrantd — 노드 에이전트. 조립만 한다. 판정은 커널이 한다.
//
// 기동 순서 (바꾸지 말 것):
//  1. loader.Load     pin 된 맵이 있으면 재사용
//  2. store.Open      캐시된 영장을 맵에 복원
//  3. loader.AttachAll
//  4. pamsock.Listen  여기 전에 로그인한 세션은 태그가 없다 (유닛에 Before=sshd.service)
//  5. ringbuf · upstream  실패해도 죽지 않는다
//
// 종료할 때 pin 은 지우지 않는다.
package main

import (
	"flag"
	"log"
)

func main() {
	var (
		pinDir     = flag.String("pin-dir", "/sys/fs/bpf/warrant", "bpffs pin 경로")
		socketPath = flag.String("pam-socket", "/run/warrantd/pam.sock", "pam_warrant.so 가 보내는 소켓")
		statePath  = flag.String("state", "/var/lib/warrantd/state.db", "bbolt 경로")
		upstreamEP = flag.String("upstream", "", "중앙 gRPC 엔드포인트. 비어 있으면 로컬 전용")
	)
	flag.Parse()

	_ = pinDir
	_ = socketPath
	_ = statePath
	_ = upstreamEP

	log.Fatal("미구현")
}
