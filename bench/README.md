# bench/

오버헤드 벤치 · 우회 시도 테스트. **초기 구조에 넣는다** — 나중에 붙이면 이미 늦다.

## 구조

```
bypass/     §04 의 우회 경로 표가 그대로 bats 테스트 케이스다
overhead/   훅별 오버헤드 실측. file_open 이 가장 위험한 미검증 가정이다
e2e/        영장 세션 부하 → 커널 판정 기록이 서버 DB 까지 빠짐없이 오는가 (맥에서 돈다)
```

## 규칙

- **§18 이 인정한 4가지 구멍은 skip 사유를 명시해 실패 테스트로 커밋한다.**
  만료 전 열어둔 fd · connect 없는 UDP · 데몬 위임 · `kubectl exec`.
  "알고 있으나 막지 못한다"와 "모른다"는 다르게 취급된다.
- 훅을 하나 붙일 때마다 `overhead/` 를 같이 돌린다. 숫자 없이 다음 훅으로 넘어가지 않는다.
- `bypass/` 는 감사 모드와 강제 모드 **양쪽에서** 돌린다.
  두 모드가 다른 답을 내면 판정 함수 공유가 깨진 것이다 (§15).

## 예 (`bypass/tag_propagation.bats`)

```bash
@test "sudo를 거쳐도 태그가 유지된다" {
  run_in_warrant_session 'sudo id -u'
  assert_tagged $(last_pid)
}

@test "systemd-run --scope는 2차 방어선에 걸린다" {
  run_in_warrant_session 'systemd-run --scope sleep 300'
  assert_tagged $(pgrep -n sleep)      # cgroup은 바뀌지만 fork 체인이 살아 있다
}
```
