#!/usr/bin/env bats
# §04 「성립 조건: 표식이 프로세스 트리를 따라가는가」 표를 그대로 옮긴 것.
#
#   세션에서 하는 행위      만드는 주체              cgroup  fork  태그
#   nohup · setsid · &      세션 자신                유지    유지  유지
#   sudo · su               세션 자신                유지    유지  유지
#   systemd-run --scope     호출자가 fork 후 이관    바뀜    유지  유지 ← 2차 방어선
#   systemd-run (기본)      PID 1                    바뀜    끊김  끊김
#   systemctl start         PID 1                    바뀜    끊김  끊김
#   at · crontab            atd · crond              바뀜    끊김  끊김
#   docker exec             containerd-shim          바뀜    끊김  끊김
#
# 앞 3줄이 초록이어야 제품이 성립한다. 뒤 4줄은 "끊긴다" 자체가 검증 대상이다.
# 그 경로의 진짜 방어선(3중 방어)은 미구현이라 맨 아래에 skip 으로 둔다.

load helpers

setup_file() { start_probe; }
teardown_file() { stop_probe; }

# ── 앞 3줄: 유지되어야 한다 ─────────────────────────────────────────

@test "§04-1 nohup 으로 분리해도 태그가 유지된다" {
    nohup sleep 811 >/dev/null 2>&1 &
    run pid_of "sleep 811"
    [ "$status" -eq 0 ]
    assert_tag "$output" yes yes
    kill_marker "sleep 811"
}

@test "§04-1 setsid 로 세션을 갈라도 태그가 유지된다" {
    setsid sleep 812 >/dev/null 2>&1 &
    run pid_of "sleep 812"
    [ "$status" -eq 0 ]
    assert_tag "$output" yes yes
    kill_marker "sleep 812"
}

@test "§04-1 백그라운드(&)로 띄워도 태그가 유지된다" {
    sleep 813 >/dev/null 2>&1 &
    run pid_of "sleep 813"
    [ "$status" -eq 0 ]
    assert_tag "$output" yes yes
    kill_marker "sleep 813"
}

@test "§04-2 sudo 로 uid 가 바뀌어도 태그가 유지된다" {
    # 1차 태그가 cgroup 에 걸려 있으므로 uid 변경과 무관해야 한다.
    sudo -n -u nobody sleep 814 >/dev/null 2>&1 &
    run pid_of "sleep 814"
    [ "$status" -eq 0 ]
    assert_tag "$output" yes yes
    kill_marker "sleep 814"
}

@test "§04-2 su 로 계정을 바꿔도 태그가 유지된다" {
    su -s /bin/sh nobody -c 'sleep 815' >/dev/null 2>&1 &
    run pid_of "sleep 815"
    [ "$status" -eq 0 ]
    assert_tag "$output" yes yes
    kill_marker "sleep 815"
}

@test "§04-3 systemd-run --scope 는 cgroup 이 바뀌어도 2차 방어선에 걸린다" {
    # 2차 방어선의 존재 이유. 호출자가 fork 한 뒤 이관하므로 fork 체인이 산다.
    command -v systemd-run >/dev/null || skip "systemd-run 없음"
    systemd-run --scope --quiet sleep 816 >/dev/null 2>&1 &
    run pid_of "sleep 816"
    [ "$status" -eq 0 ]
    assert_tag "$output" no yes
    kill_marker "sleep 816"
}

# ── 뒤 4줄: 끊긴다. 그게 검증 대상이다 ──────────────────────────────

@test "§04-4 systemd-run (기본) 은 PID 1 이 fork 하므로 태그가 끊긴다" {
    command -v systemd-run >/dev/null || skip "systemd-run 없음"
    systemd-run --quiet --unit=wb-test-817 sleep 817 >/dev/null 2>&1 || true
    run pid_of "sleep 817"
    [ "$status" -eq 0 ]
    assert_tag "$output" no no
    systemctl stop wb-test-817 2>/dev/null || true
}

@test "§04-5 systemctl start 는 PID 1 이 fork 하므로 태그가 끊긴다" {
    skip "유닛 파일 픽스처가 필요하다. §04-4 가 같은 경로(PID 1 위임)를 이미 덮는다"
}

@test "§04-6 at 은 atd 가 fork 하므로 태그가 끊긴다" {
    command -v at >/dev/null || skip "at 없음 (apt install at)"
    systemctl is-active --quiet atd || skip "atd 가 안 돌고 있다"
    echo 'sleep 818' | at now 2>/dev/null
    run pid_of "sleep 818"
    [ "$status" -eq 0 ]
    assert_tag "$output" no no
    kill_marker "sleep 818"
}

@test "§04-7 docker exec 은 containerd-shim 이 fork 하므로 태그가 끊긴다" {
    command -v docker >/dev/null || skip "docker 없음"
    docker info >/dev/null 2>&1 || skip "docker 데몬이 안 돈다"
    docker run -d --rm --name wb-test-819 alpine sleep 900 >/dev/null 2>&1 || skip "컨테이너 기동 실패"
    docker exec -d wb-test-819 sleep 819 2>/dev/null || true
    run pid_of "sleep 819"
    [ "$status" -eq 0 ]
    assert_tag "$output" no no
    docker rm -f wb-test-819 >/dev/null 2>&1 || true
}

# ── 위임 경로의 진짜 방어선 — 아직 구현 전 ──────────────────────────
# 실행 허용 목록이 화이트리스트라, 영장에 없는 위임 도구는 bprm_check_security 에서 막힌다 (§04).

@test "§04 위임-1 화이트리스트에 없는 systemd-run 은 exec 에서 막힌다" {
    skip "실행 화이트리스트 미구현. lsm/bprm_check_security 는 지금 기록만 한다 (감사 모드)"
}

@test "§04 위임-2 /run/systemd/private 로의 AF_UNIX 연결이 차단된다" {
    skip "lsm/socket_connect 미구현. 훅 부착 순서상 file_open 다음이다"
}

@test "§04 위임-3 read-only 영장에서 /var/spool 쓰기가 차단된다" {
    skip "쓰기 규칙 미구현. S1 이 file_open 오버헤드를 판정한 뒤에 붙는다"
}
