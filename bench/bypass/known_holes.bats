#!/usr/bin/env bats
# §18 「아직 못 메운 곳」 — 문서가 인정한 네 구멍.
# 전부 skip 이지만 사유를 명시해 커밋한다 — "알고 있으나 막지 못한다"와 "모른다"는 다르다.
# 넷 다 감사 모드에서 기록은 된다. 막지 못할 뿐 보이지 않는 건 아니다.

load helpers

@test "§18-1 만료 전에 열어둔 쓰기 fd 로는 만료 후에도 쓸 수 있다" {
    skip "구조적 구멍. file_open 은 여는 순간만 본다 — 이미 열린 fd 로의 write 는 훅을 거치지 않는다. \
file_permission 은 read/write 마다 불려서 너무 비싸다. 답은 on_expiry=강제종료 옵션이거나 감사 기록뿐이다 (§18)"
}

@test "§18-2 connect 없는 UDP 전송은 socket_connect 를 거치지 않는다" {
    skip "구조적 구멍. sendto 는 socket_connect 를 안 탄다 — DNS 터널링 경로다. \
답은 lsm/socket_sendmsg 추가인데 비용이 오르므로 영장에 플래그가 있을 때만 attach 한다 (§18)"
}

@test "§18-3 다른 데몬에 위임하면 cgroup 과 fork 체인이 동시에 끊긴다" {
    skip "부분적으로 막힌다. PID 1·atd·containerd-shim 이 대신 fork 하는 경우다 — \
tag_propagation.bats 의 §04-4·6·7 이 '끊긴다'는 사실 자체를 이미 검증한다. \
현실적 봉쇄는 실행 화이트리스트+소켓 차단+spool 차단의 3중 방어이고, \
완전한 승계(D-Bus JobNew/UnitNew 구독)는 Phase 2 다 (§18)"
}

@test "§18-4 kubectl exec 은 컨테이너 cgroup 에서 태어나 세션 scope 가 없다" {
    skip "미착수. 답은 API 서버 감사 웹훅으로 '누가 어느 파드에'를 받아 \
다음 runc exec 에 바인딩하는 것이고 Phase 2 다. 이 리포에 k8s 환경이 없다 (§18)"
}
