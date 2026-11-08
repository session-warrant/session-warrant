# 핵심 흐름

코드가 실제로 어떤 순서로 도는지 흐름별로 적은 문서다. 설계 의도는 `session-warrant-plan.html`(§ 번호),
실측 근거는 `experiments.md` 에 있다. 여기 적은 함수 이름과 줄 위치는 2026-11-07 `main` + `warrant-subscribe` 기준이다.
**코드를 고쳐 흐름이 바뀌면 이 문서도 같이 고친다.**

| # | 흐름 | 한 줄 |
|---|---|---|
| 1 | [warrantd 기동](#1-warrantd-기동) | 순서가 곧 태깅 공백 방지다 |
| 2 | [영장 받기와 설치](#2-영장-받기와-설치) | 중앙 push → 서명 검증 → 규칙 → 영장 → `active_flag` |
| 3 | [세션 결속](#3-세션-결속) | SSH 로그인 → cgroup id → 영장 태그 |
| 4 | [커널 판정](#4-커널-판정) | 시스템 호출마다, 유저 공간 왕복 없이 |
| 5 | [태그 전파 (fork)](#5-태그-전파-fork) | cgroup 을 벗어나도 표식이 따라간다 |
| 6 | [만료 · 취소](#6-만료--취소) | 열린 세션 안에서 바로 먹는다 |
| 7 | [자기보호](#7-자기보호) | 영장 세션이 집행 장치를 못 끄게 |
| 8 | [무영장 세션 → 서버](#8-무영장-세션--서버) | 감사 큐 → gRPC → DB → Grafana |
| 9 | [커널 기록과 유실 구간](#9-커널-기록과-유실-구간) | ringbuf 소비, 빠진 번호 = 유실 |
| 10 | [정책 컴파일과 inode 감시](#10-정책-컴파일과-inode-감시) | 경로 → `(dev, ino)`, 파일이 바뀌면 다시 |
| 11 | [실패할 때](#11-실패할-때) | 집행은 단단하게, 발급은 느슨하게 |

---

## 1. warrantd 기동

```
systemd (Type=notify, Before=ssh.service)
   │
   ▼
run()
   │ 1. BPF LSM 켜져 있나          /sys/kernel/security/lsm 에 bpf
   │ 2. loader.LoadObject          pin 된 맵이 있으면 재사용 (재시작해도 태그 유지)
   │ 3. bpfmap.Open
   │ 4. 영장 설치                   로컬 파일 → registry.install
   │    settleActive               파일 영장도 구독도 없으면 active_flag 끄기
   │ 5. AttachAll + checkAttached  pin 된 링크는 재사용 (훅 이중 부착 없음)
   │ 6. pamsock.Listen             ← 이 뒤부터 오는 세션은 태그된다
   │ 7. ringbuf 소비 · upstream     실패해도 계속
   │ 8. sd_notify READY=1           ← 이제야 sshd 가 뜬다
   ▼
for-select (종료 신호 · 소켓 오류 · ringbuf 오류)
```

| 단계 | 실패하면 | 이유 |
|---|---|---|
| 1 ~ 3, 5, 6 | warrantd 종료 → systemd 가 1초 뒤 재시작 | 이게 없으면 판정이나 태깅이 아예 안 된다 |
| 4 (영장) | 그 영장만 건너뛰고 계속 | 발급 경로는 느슨하게 실패한다 (§17) |
| 5 (훅 개수) | 미러만 빠졌으면 경고 후 계속, 그 밖은 종료 | 미러는 대조용이다. LSM 훅이 빠지면 자기보호가 빠진 채로 돈다 (§16) |
| 7 | 로그만 남기고 계속 | 감사 업로드가 죽어도 커널 집행은 계속된다 |

- **영장을 훅보다 먼저 넣는다.** 훅이 붙은 뒤에 넣으면 그 사이 판정이 영장 없이 돈다.
- **소켓을 연 뒤에 READY 를 보낸다.** 먼저 보내면 sshd 가 떠서 받은 세션이 태그 없이 시작된다.
- 유닛에 `Before=ssh.socket` 은 넣지 않는다. 순서 순환이 생겨 sshd 가 안 뜬 적이 있다 (`deploy/README.md`).
- 종료할 때 pin 은 지우지 않는다. warrantd 가 죽어도 커널은 계속 판정한다.

코드: `agent/cmd/warrantd/main.go` `run` · `checkAttached`(hooks.go) · `settleActive`

---

## 2. 영장 받기와 설치

서버 쪽 앞단: 콘솔에서 **신청**(REQUESTED, 서명 없음) → **다른 사람이 승인**(본인이면 403) → 그 순간부터 기간 시작 ·
protobuf 로 굳혀 Ed25519 서명 → 커밋 뒤 아래 스트림으로 push. 신청 · 발급 · 반려 · 회수는 계보에 누가 했는지와 함께 남는다
(`server/README.md` 「영장 발급」). 아래는 노드가 받는 쪽이다.

```
중앙 WarrantPushService.Subscribe (스트림)
   │  활성 집합 전체 → ResyncComplete → 이후 변경분
   ▼
upstream.Subscribe ── 끊기면 1s → 2s → … → 30s 로 다시 붙는다
   │ 영장 하나마다
   ▼
registry.Apply
   │ ① upstream.Verify       Ed25519 서명 (key_id 로 고른 키, 받은 바이트 그대로)
   │ ② checkWarrant          대상 호스트 · warrant_id · policy_id · 만료 있음 · ENFORCE 아님 · break_glass 아님
   │ ③ revision              가진 것보다 커야 한다
   │ ④ 정책                  처음 보는 policy_id → policyInstaller.install → 규칙 맵
   │                         이미 있는 id 에 다른 규칙 → 거부
   │ ⑤ kernelWarrant         만료 시각 Unix → boot 기준
   │ ⑥ PutWarrant            warrants[warrant_id] = struct warrant (32바이트)
   │ ⑦ SetActive(true)       첫 영장일 때 한 번
   ▼
ResyncComplete{active_count}
   │ 검증된 수 < active_count ?  → 건너뛴다 (아무것도 취소 안 함, RESYNC SKIPPED 로그)
   ▼
registry.Resync(이번 스트림에서 검증된 id 들)
   집합에 없는 중앙 영장 → Revoke (지우지 않는다)
```

| 단계 | 어긋나면 | 이유 |
|---|---|---|
| ① 서명 | 거부, 커널에 아무것도 안 씀. Resync 집합에도 안 넣음 | 서명 없는 메시지로 영장을 만들거나 살려 둘 수 없어야 한다 |
| ② 검사 | 거부 | 이번 학기는 감사 모드까지다. 강제 · break_glass 는 받지 않는다 |
| ③ revision | 거부 | 늦게 도착한 옛 revision 이 연장 · 취소를 되돌리면 안 된다 |
| ④ 같은 id 다른 규칙 | 거부 | 같은 정책을 쓰는 다른 영장들의 규칙이 몰래 바뀐다 |
| ④ 규칙 컴파일 실패 | 그 영장은 안 넣음 | 규칙 없는 영장은 전부 거부로 판정된다 |

- **규칙을 먼저, 영장을 나중에 넣는다.** 반대면 영장은 있는데 규칙이 없는 순간이 생긴다.
- **시각 변환은 여기서만 한다.** `만료(boot) = 지금 boot + (만료 Unix − 지금 Unix)`. 이미 지났으면 1 (0 은 "만료 없음").
  커널은 벽시계를 믿지 않고 `bpf_ktime_get_boot_ns()` 와 비교한다.
- **Resync 에서 지우지 않고 취소한다.** 맵에서 지우면 이미 태그된 세션의 조회가 빗나가 「관리 대상 아님」으로 통과한다.
  취소로 남기면 그 세션은 끊긴다. 같은 이유로 `active_flag` 도 다시 끄지 않는다.
- **검증된 수가 서버가 말한 수보다 적으면 Resync 를 건너뛴다.** 키를 교체했는데 노드에 옛 키만 있으면 push 가 전부
  거부되고, 그 빈 집합으로 Resync 하면 노드의 중앙 영장이 전부 취소된다 — 발급 쪽 설정 실수가 집행을 무너뜨린다 (§17).
  가짜 메시지를 끼워 넣어도 진짜 영장의 검증 수는 줄지 않으므로, 끼워 넣기로 정당한 취소를 막을 수는 없다.
- 로컬 파일(`-warrants`)도 ②부터 같은 길을 탄다. 서명이 없어서 Resync 는 파일 영장을 건드리지 않는다.
- 중앙 영장은 `-trust-keys` 에 키가 있을 때만 받는다. 키가 없으면 구독하지 않는다.

코드: `agent/internal/upstream/subscribe.go` · `verify.go`, `agent/cmd/warrantd/registry.go` `Apply` · `install` · `Resync`,
`warrants.go` `checkWarrant` · `kernelWarrant`

---

## 3. 세션 결속

```
ssh 로그인
   │
   ▼
sshd PAM session 단계
   │ pam_systemd.so       session-N.scope 생성 (cgroup)
   │ pam_warrant.so       XDG_SESSION_ID → /sys/fs/cgroup/user.slice/user-UID.slice/session-N.scope
   │                      stat → st_ino = cgroup id
   │                      "OPEN \t 세션 \t cgroup \t 계정 \t 출발지 \t SSH_AUTH_INFO_0"
   │                      유닉스 데이터그램, MSG_DONTWAIT. 응답을 기다리지 않는다
   │                      → 항상 PAM_SUCCESS
   ▼
warrantd pamsock.Serve
   │ parse
   ▼
binder.Bind
   │ Fingerprint           auth info 의 공개키 → "SHA256:…"
   │ registry.match        계정 + 지문 일치 · 취소 · 만료 아님 · 여럿이면 늦게 끝나는 쪽
   │
   ├─ 맞음 ──▶ TagCgroup   cgroup_warrant[cgroup id] = warrant_id
   │                       실패하거나 cgroup id 가 0 이면 → 무영장으로 기록
   │
   └─ 안 맞음 ─▶ 무영장 기록 (사유 NO_KEY · KEY_MISMATCH · NO_WARRANT) → 흐름 8

로그아웃: "CLOSE \t 세션 \t cgroup" → binder.Unbind → UntagCgroup
```

| 사유 | 조건 |
|---|---|
| `NO_KEY` | auth info 에 공개키가 없다 (암호 로그인 등) |
| `KEY_MISMATCH` | 그 계정에 살아 있는 영장은 있는데 키가 다르다. 남의 영장에 편승하려는 것 |
| `NO_WARRANT` | 그 계정에 영장이 없다. 맞았는데 태그를 못 붙인 경우도 이걸로 남긴다 |

- **키는 cgroup id 다. 세션 번호가 아니다.** `XDG_SESSION_ID` 는 재사용된다. 세션 번호에 걸면 다음 세션이 남의 영장을
  물려받는다 (S3 실측: 같은 `session-4.scope` 가 세 번 다 다른 cgroup id).
- `pam_warrant.so` 는 `pam_systemd.so` 뒤에 온다. 그 시점에 scope 가 이미 있다 (S3: 11/11, 대기 0).
- **PAM 은 실패해도 로그인을 막지 않는다.** warrantd 가 없으면 데이터그램이 버려지고 세션은 태그 없이 시작된다 (§17).
- 커널에 붙는 건 `cgroup → warrant_id` 한 줄이다. 영장 내용은 흐름 2 에서 이미 맵에 있다.
- 결속은 로그인 순간에만 일어난다. 이미 열린 세션에 나중에 온 영장은 붙지 않는다.
- `Unbind` 는 cgroup 태그만 지운다. fork 로 퍼진 태그(흐름 5)는 그 프로세스가 죽어야 사라진다.

코드: `pam/pam_warrant.c` `pam_sm_open_session` · `wr_cgid`, `agent/internal/pamsock/pamsock.go` `Serve` · `parse` · `Fingerprint`,
`agent/cmd/warrantd/binder.go` `Bind` · `Unbind`

---

## 4. 커널 판정

모든 판정 훅이 같은 앞부분을 지난다.

```
시스템 호출 (execve · open(쓰기) · unlink · connect …)
   │ DAC 권한 검사 통과 뒤 LSM 훅 → uid 0 에도 적용된다
   ▼
lookup_warrant
   │ ① active_flag == 0 ?              → 통과 (영장이 하나도 없는 노드)
   │ ② cgroup_warrant[내 cgroup]       1차 표식
   │ ③ 없으면 task_warrant[current]    2차 표식 (흐름 5)
   │    둘 다 없으면                    → 통과 (관리 대상 아님)
   │ ④ warrants[warrant_id]
   ▼
훅별 판정 (아래 표)
   │ validity        revoked → 1 · boot now > expires_ns → 2 · 아니면 0
   │ 규칙 조회        rule_exec · rule_write · rule_net (키 앞부분 = policy_id)
   ▼
emit → ringbuf     기록 규칙에 따라 (흐름 9)
   ▼
ret_of             거부 + mode == ENFORCE 일 때만 -EPERM. OBSERVE · DRYRUN 은 0
```

| 훅 | 앞문 | 판정 | 기록 |
|---|---|---|---|
| `bprm_check_security` (실행) | — | 바이너리 `(dev, ino)` 가 `rule_exec` 에 있나 | **허용도 기록** (빈도 낮음) |
| `file_open` | `f_mode & FMODE_WRITE` 아니면 통과 | 그 파일에서 위로 올라가며 `rule_write` 를 찾는다 (최대 16단). 처음 걸린 규칙이 답, 없으면 거부 | 거부만 |
| `inode_{create,unlink,rename,link,symlink}` | — | `file_open` 과 같은 디렉터리 순회 | 거부만 |
| `socket_connect` | IP 가 아니면 AF_UNIX 위임 소켓만 본다 | `rule_net` (LPM, IPv4 는 `::ffff:` 로 편다) + 포트 · 프로토콜 | **허용도 기록** (AF_UNIX 는 거부만) |
| `socket_sendmsg` | 정책의 `inspect_udp` 가 켜졌고, 주소가 붙은 송신일 때만 | `rule_net` | 거부만 |

| validity | 실행 | 쓰기 · inode · 아웃바운드 |
|---|---|---|
| 0 유효 | 규칙대로 | 규칙대로 |
| 1 취소 | 거부 | 거부 |
| 2 만료 (DEMOTE) | 통과 | 거부 |

- **판정 중에 유저 공간으로 올라가지 않는다.** warrantd 가 죽어도, 중앙이 끊겨도 이미 맵에 있는 영장은 계속 집행된다.
- `file_open` 은 영장 조회 뒤에 쓰기 비트를 본다. 영장 없는 프로세스는 ①~③ 에서 끝나고, 영장 있는 프로세스의
  읽기는 쓰기 비트에서 끝난다 (S1: 읽기 지배 워크로드에서 C · E · D 가 같다).
- 쓰기 규칙: `recursive` 가 아니면 직계 자식까지만. 금지 규칙은 반드시 디렉터리 inode 다 (흐름 10).
- **감사 · 드라이런 · 강제가 같은 판정 함수를 쓴다.** 모드는 마지막 `ret_of` 에서만 갈린다. kprobe 미러 4종이 같은 함수를
  다시 불러 LSM 판정과 대조하고, 미러는 판정을 되돌리지 않는다.
- AF_UNIX 는 화이트리스트가 아니다. `/run/dbus/` · `/run/docker.sock` · `/run/containerd/` · `/run/systemd/private` 만 끊는다
  (세션 밖으로 일을 넘기는 통로, §04). **알려진 결함 2건이 있다** — `/run/systemd/private` 비교가 한 칸 밀려 있고,
  `/var/run/…` 경로는 안 본다 (`warrant.bpf.c` `connect_verdict`).

코드: `bpf/warrant.bpf.c` `lookup_warrant` · `validity` · `ret_of` · `bprm_verdict` · `file_verdict` · `dentry_write_allowed` ·
`inode_verdict` · `connect_verdict`

---

## 5. 태그 전파 (fork)

```
태그된 프로세스가 fork
   │
   ▼
tp_btf/sched_process_fork          ← active_flag 를 보지 않는다
   │ 부모의 task_warrant 가 있으면 그걸, 없으면 cgroup_warrant[현재 cgroup]
   │ 둘 다 없으면 끝
   ▼
task_warrant[자식] = warrant_id    자식의 task local storage
   ▼
emit FORK (ALLOW)
```

| 경로 | 1차 (cgroup) | 2차 (task) | 결과 |
|---|---|---|---|
| `sudo` · `su` · `nohup` · `setsid` · `&` | 유지 | 유지 | 표식 유지 (uid 가 바뀌어도) |
| `systemd-run --scope` | 끊김 | **유지** | 2차 방어선이 잡는다 |
| `systemd-run`(기본) · `docker exec` · `at` · `cron` | 끊김 | 끊김 | 위임 경로. 실행 화이트리스트 · AF_UNIX 차단으로 막는다 |

- cgroup 은 uid 와 무관하다. 그래서 `sudo` 를 해도 1차 표식이 그대로다 (S2).
- 2차 표식은 부모 → 자식으로만 복사된다. cgroup 을 갈아탄 뒤에도 fork 체인만 이어져 있으면 따라간다 (S2 의 가장 값진 한 줄).
- 전파는 `active_flag` 와 무관하게 돈다. 플래그를 껐다 켜도 그 사이 태어난 자식이 표식을 잃지 않는다.

코드: `bpf/warrant.bpf.c` `warrant_fork`

---

## 6. 만료 · 취소

```
만료                                  취소
중앙: expires_at (Unix)               중앙: 새 revision, revoked = true
   │ 흐름 2 에서 boot 기준으로 변환       │ 흐름 2 (revision 이 커야 한다)
   ▼                                    ▼
warrants[id].expires_ns              warrants[id].revoked = 1
   │                                    │
   └──────────────┬─────────────────────┘
                  ▼
     다음 판정에서 validity 가 1 · 2 를 돌려준다 (흐름 4)
     타이머도, 프로세스 순회도, 유저 공간 왕복도 없다
```

- **열린 세션 안에서 바로 먹는다.** 기존 JIT 권한은 "다음 접속"을 막는 데 그친다. 여기서는 다음 시스템 호출부터다.
  (2026-11-07 VM: 취소 push 직후 같은 세션의 실행 · 쓰기가 전부 `DRY-DENY`.)
- 만료는 `on_expiry` 가 의미를 정한다. 커널은 DEMOTE 기준으로 실행만 살리고 나머지를 막는다.
  KILL · SESSION_ONLY_GRACE 에서 실제로 프로세스를 죽이는 건 warrantd 몫이고 **아직 없다.**
- 서버 활성 집합에서 빠진 영장도 취소로 처리한다 (흐름 2 Resync).
- binder 는 취소 · 만료된 영장을 새 세션에 붙이지 않는다.

코드: `bpf/warrant.bpf.c` `validity`, `agent/cmd/warrantd/warrants.go` `kernelWarrant` · `matchWarrant`, `registry.go` `Resync`

---

## 7. 자기보호

```
영장 세션 안에서
  bpf()  ·  kill  ·  umount  ·  ptrace  ·  모듈 요청       → LSM 훅 5종
  /var/lib/warrantd · /run/warrantd · /etc/warrantd 쓰기   → rule_write DENY (모든 정책에 강제 삽입)
   │
   ▼
selfprotect
   │ lookup_warrant          영장 없으면 통과 (자기보호 대상이 아니다)
   │ break_glass 면 통과
   │ kill · ptrace 는 상대를 본다: 상대가 같은 영장 cgroup 이면 통과
   │ 같은 pid · 훅은 1초에 한 번만 기록
   ▼
거부 (ENFORCE 에서만 -EPERM)
```

- **정책이 아니라 제품이 넣는다.** 영장 작성자가 실수로도 열 수 없어야 하고, 하나라도 빠지면 나머지가 무의미하다 (§16).
- kill · ptrace 를 상대 기준으로 좁힌 건 S5 실측 때문이다. 무조건 막으면 강제 모드에서 `sudo` · `ps` · Ctrl-C 까지 죽는다.
  상대는 cgroup 으로만 본다 — 2차 표식만 가진 같은 영장 프로세스는 「밖」으로 보이는데, 막는 쪽 오판이라 약해지지 않는다.
- 감사 · 드라이런 영장에서는 기록만 한다. 실제로 막는 건 강제 모드에서다.

코드: `bpf/warrant.bpf.c` `selfprotect` · `peer_outside_warrant`, `agent/internal/policy/policy.go` `DefaultDenyWrite`

---

## 8. 무영장 세션 → 서버

```
binder.unwarranted                   (흐름 3 에서 영장이 안 맞음)
   │ AuditEvent{HOOK_AGENT, ALLOW, warrant 0, UnwarrantedSession{사유, 계정, 지문, 출발지, cgroup}}
   ▼
store.AuditQueue.Append              node_seq 를 매긴다. 상한 10,000 — 넘치면 오래된 것부터 버리고
   │                                 그 구간을 LOCAL_STORE_FULL gap 으로 남긴다
   ▼
upstream.StreamAudit                 첫 배치에 NodeHello. 최대 500건씩
   │ AuditBatch{events, gaps, last_node_seq, seq_epoch}
   ▼
서버 AuditIngestGrpcService
   │ AuditIngestService.ingest       (node, seq_epoch, node_seq) 로 멱등 저장
   │ 저장이 끝난 뒤에만 ack
   ▼
AuditAck{seq_epoch, acked_through} → AuditQueue.Ack → 그 번호까지 지운다
   ▼
PostgreSQL unwarranted_session → Grafana 「무영장 세션」 → 경보(웹훅)
```

- **재전송이 전제다.** 스트림이 끊기면 마지막 ack 다음부터 다시 보낸다. 서버는 같은 키를 두 번 받아도 한 번만 저장한다.
- **seq_epoch 는 0 이면 안 된다.** warrantd 프로세스마다 새로 뽑는다 — 재시작해서 node_seq 가 1 로 돌아가도 옛 키와 안 겹친다.
  다른 epoch 의 ack 로는 지우지 않는다.
- 이 경로는 커널 ringbuf 를 거치지 않는다. 무영장 판정은 PAM 쪽 binder 가 한다 (4주 차 마일스톤).
- 큐가 메모리라서 warrantd 가 재시작하면 ack 안 된 기록을 잃는다. bbolt `store` 가 생기면 닫힌다.

코드: `agent/cmd/warrantd/binder.go` `unwarranted` · `unwarrantedEvent`, `agent/internal/store/auditqueue.go`,
`agent/internal/upstream/audit.go` `StreamAudit`, `server/…/grpc/AuditIngestGrpcService.java`, `application/AuditIngestService.java`

---

## 9. 커널 기록과 유실 구간

```
emit (커널)
   │ ① cpu_seq += 1        번호를 먼저 올린다
   │ ② ringbuf reserve     실패하면 그냥 끝 — 번호는 이미 소비됐다
   │ ③ boot_ts · warrant · 프로세스 · 훅 · 판정 · payload
   ▼
ringbuf.Consumer.Run (warrantd)
   │ (cpu, cpu_seq) 가 기대한 다음 번호인가
   │   건너뛰었으면 → Gap{from = 그 CPU 의 마지막 레코드 시각, to = 건너뛴 레코드 시각, dropped}
   ▼
logRecord → journal                  ← 지금은 여기까지. 서버로는 아직 안 올린다
```

- **번호를 먼저 올리는 게 핵심이다.** reserve 가 성공한 뒤에 올리면, 버려진 이벤트가 번호도 남기지 않고 사라진다.
- 빈 구간을 숨기지 않는다 (§13). 유실은 「조용한 시간」과 구분되어야 한다.
- Gap 시각은 boot 기준이다(`FromBootNs` · `ToBootNs`). 서버로 올리는 쪽이 벽시계로 바꿔 `from_unix_ns` 에 넣어야 한다.
- 기록 절제: 차단은 전건, 허용은 실행 · 접속 · fork 만. 허용된 쓰기까지 남기면 ringbuf 가 넘쳐 정작 차단 기록이 밀린다.
- 미러(kprobe) 레코드는 `logRecord` 가 건너뛴다. 대조용이다.

코드: `bpf/warrant.bpf.c` `emit`, `agent/internal/ringbuf/ringbuf.go` `Run` · `checkGap`, `agent/cmd/warrantd/main.go` `logRecord` · `logGap`

---

## 10. 정책 컴파일과 inode 감시

```
pb.Policy (경로 · CIDR)
   │ policySpec
   ▼
policy.Compile
   │ 기본 허용 추가       /etc/shells 의 로그인 셸 (NoDefaultExec 로 끔) · /dev/null · /dev/pts …
   │ 기본 금지 추가       warrantd 자기 디렉터리 3곳 (자기보호 6번째)
   │ 경로마다 stat 한 번  → (dev, ino) · 디렉터리인가 · setuid 인가
   │   금지 규칙이 파일이면 거부 — 디렉터리여야 한다
   │ 조합 경고           예: systemctl 실행 허용 + /etc/systemd/system 쓰기 허용
   ▼
Compiled.Apply           쓰기 금지 → 쓰기 허용 → 실행 → 네트워크
   ▼
Watcher.Watch            10초마다 다시 stat
   │ inode 가 바뀌었거나 경로가 사라졌으면
   ▼
policyInstaller.recompile → Compile → Apply (같은 policy_id 로 덮어쓴다)
```

- **경로가 아니라 `(dev, ino)` 다.** 커널은 경로 문자열을 다루지 않는다. 바이너리를 다른 이름으로 복사해도 inode 가 달라 걸린다.
- **금지는 디렉터리 inode 다.** 파일 inode 로 금지하면 `mv` 후 같은 이름으로 다시 만들면 뚫린다 (§15).
- 검사와 맵 값이 같은 stat 에서 나온다 (PR #9). 그 사이에 경로가 갈려도 검사를 통과한 inode 와 맵의 inode 가 같다.
- **알려진 사각지대:** ext4 는 지운 inode 번호를 바로 재사용한다. 지우고 같은 자리에 만들면 번호가 같아 Watcher 가 못 본다
  (`TestWatcherMissesInodeReuse`). S4 가 이 범위를 잰다.
- warrantd 유닛에 `PrivateTmp` · `ProtectHome` 을 넣지 않는다. 넣으면 warrantd 가 세션과 다른 `/tmp` · `/home` 을 보고
  엉뚱한 inode 로 컴파일한다.

코드: `agent/cmd/warrantd/warrants.go` `policySpec`, `registry.go` `policyInstaller`, `agent/internal/policy/policy.go` `Compile` · `Apply` · `Watcher`

---

## 11. 실패할 때

**집행 경로(커널)는 단단하게, 발급 경로(PAM · 중앙)는 느슨하게 실패한다 (§17).**

| 무엇이 죽나 | 무엇이 일어나나 |
|---|---|
| 중앙 서버 | 이미 맵에 있는 영장은 계속 집행. 새 발급 · 취소만 안 온다. 감사는 큐에 쌓였다가 재연결 뒤 재전송 |
| warrantd | 커널은 pin 된 맵으로 계속 판정. 새 로그인은 태그 없이 시작되고 무영장 기록도 안 남는다. systemd 가 1초 뒤 재시작 |
| PAM → warrantd 소켓 | **로그인 허용.** 세션은 태그 없이 시작. fail-close 면 장애 때 아무도 못 들어간다 |
| 영장 하나의 정책 컴파일 | 그 영장만 안 들어간다. 나머지는 계속 |
| ringbuf 넘침 | 번호가 건너뛰어 Gap 으로 드러난다 |
| 감사 큐 넘침 | 오래된 것부터 버리고 `LOCAL_STORE_FULL` gap 으로 남긴다 |
| LSM 훅 하나 부착 실패 | warrantd 가 뜨지 않는다. 자기보호가 빠진 채로 도는 게 제일 위험하다 |
| kprobe 미러 부착 실패 | 경고만. 대조가 빠질 뿐 판정은 그대로 |

### 아직 없는 것 (흐름이 끊기는 곳)

- **bbolt `store`:** 재시작한 warrantd 는 전에 받은 중앙 영장을 모른다. warrantd 가 꺼진 동안 서버에서 취소된 영장은
  맵에서 만료될 때까지 산다. 감사 큐도 재시작하면 잃는다.
- **커널 기록 업로드:** 흐름 9 의 레코드가 journal 에서 멈춘다. 서버로 가는 건 흐름 8 의 무영장 세션뿐이다.
- **영장 세션 기록:** 영장이 맞은 세션은 서버에 안 올라간다. 「조직 전체 SSH 접속 현황」을 셀 수 없다.
- **mTLS · Heartbeat · 연장 요청 · LookupActiveWarrant** (`upstream`).
- **KILL · SESSION_ONLY_GRACE 만료 처리** (흐름 6).
