# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Session Warrant

SSH 세션에 범위·유효기간을 가진 **영장(warrant)** 을 붙이고, 그 영장을 셸이 아니라 **커널(eBPF LSM)** 이 집행하는 서버 접근통제 제품.
기존 게이트웨이/프록시형 SSH 접근제어(Teleport, StrongDM 등)가 못 하는 "문을 통과한 다음"을 통제한다.

- `docs/session-warrant-plan.html` — 개념·기획·아키텍처 통합본 (r09, 2026-08-15). 절 번호(§01~§19)로 참조된다.
- `docs/session-warrant-tech-stack.html` — 기술 스택 선택과 근거 (2026-08-19).
- `docs/session-warrant-ebpf-fields.html` — BPF가 뽑아내는 값 전체 목록 (§01~§14).
- `docs/session-warrant-qa.html` — 심사 질의 대응 30문항. 짧은 답 + 절 번호·실측 근거 (2026-09-10).
- `docs/session-warrant-progress.html` — 지도교수 진행 보고서, 경어체. 스파이크 3/4 통과 · 계층별 상태 · 정정 사항 · 4주 계획 (2026-09-10).
- `docs/session-warrant-pitch.html` — 10분 발표용 기획 의도·목표. 분 단위 시간 배분, 화살표 키 이동, T 키 타이머 (2026-09-10).
- `docs/experiments.md` — **S0~S4 실험 기록.** 결론만이 아니라 틀렸던 중간 결론과 그걸 알아낸 방법까지. 아래 「~에서 실측된 것」 절들의 원본이다.

문서들은 서로를 절 번호로 상호 참조한다. 설계 관련 판단이 필요하면 추측하지 말고 해당 절을 먼저 읽을 것.

## 이번 학기 산출물의 범위 (먼저 읽을 것)

**졸업프로젝트 산출물은 「감사 모드까지」다. 강제 모드(`-EPERM`)는 범위 밖이다.**

기획서 §09의 MVP는 감사 2개월 → 무영장 탐지 +1개월 → 강제 +2개월, **총 5개월을
3인 분업**으로 잡은 일정이다. 지금은 1인이고 스파이크도 진행 중이다. 한 학기에
강제 모드까지 가려다 어느 것도 못 끝내는 쪽이 훨씬 큰 위험이다.

| | 이번 학기 | 범위 밖 |
|---|---|---|
| LSM 훅 | 붙이고 **`return 0`** — 기록만 | `-EPERM` 반환 |
| 태그 두 겹 | cgroup + fork 전파, §04 표 검증 | D-Bus 승계(Phase 2) |
| 오버헤드 | 훅별 실측, p99까지 | — |
| 발급 경로 | 중앙 → warrantd → 맵 | Slack 승인 연동 |
| 자기보호 6종 | 설계·문서화 | 구현 |

**이건 축소가 아니라 §09가 이미 승인한 선이다.** 기획서: *"감사 모드에서 멈춰도
제품이 미완성이 아니라는 게 이 계획의 성질이다."* 감사 모드만으로도
"영장 없는 접속 탐지"와 "조직 전체 SSH 접속 현황 리포트"가 나온다.

범위를 **말하지 않으면** "강제 모드 못 했네요"가 되고, **먼저 말하면**
"설계 단계에서 범위를 잘랐네요"가 된다. 같은 결과물이다.

강제 모드로 넘어가는 조건은 하나다 — **자기보호 6종(§16)이 전부 붙은 뒤.**
하나라도 빠진 채 `-EPERM`을 켜면 verifier를 통과한 버그 하나로 자기 박스에서
잠긴다. 이 순서는 일정과 무관하게 지킨다.

## 현재 상태 (2026-09-08)

**S0 · S1 · S2 · S3 전부 통과. 남은 스파이크는 S4 뿐이고, 그건 제품 코드와 병행 가능하다.**
BPF LSM이 붙고 돌고, 쓰기 포화 조건에서 오버헤드가 **1% 미만**이며, 태그 두 겹이 §04 표대로 동작하고,
PAM session 단계에서 `session-N.scope` 가 이미 확정돼 있다(태깅 공백 없음).
실험 경위 전체는 `docs/experiments.md` 에 있다.

| 계층 | 상태 |
|---|---|
| `bpf/` | `smoke.bpf.c` + 로더 — **동작 확인됨**. 제품 코드는 아직 없다 |
| `deploy/` | `bootstrap.sh` · `enable-bpf-lsm.sh` — 동작 |
| `server/` | Java 클래스 골격 52개 (시그니처 + 의사코드 주석, 본문 미구현). **빌드·의존성 해결 확인됨** — `bootJar` 까지 통과 |
| `bench/overhead/` | S1 하네스 — 3차 실행 완료(티어 E 포함). **최악 조건 1% 미만 — S1 통과** |
| `bench/bypass/` | S2 §04 표 = bats 13케이스 + §18 4구멍(skip). **8 통과 · 0 실패**, 출력 커밋됨. 진짜 세션으로 재확인 남음 |
| `bench/pamtiming/` | S3 하네스 — **통과**. sshd 11/11, 태깅 공백 없음 |
| `bench/inode/` | S4 하네스 — fanotify 감시자 + 변형 카탈로그. **아직 안 돌렸다** |
| `web/` | 감사 4화면(개요·검색·세션 타임라인·무영장). React 19 + shadcn, **빌드 확인됨**. 목 데이터 |
| `proto/` `agent/` `pam/` | 디렉터리 + `README.md` 만. 코드 없음 |

각 디렉터리의 `README.md` 에 그 계층이 지켜야 할 제약이 적혀 있다. 작업 전에 해당 README를 먼저 읽을 것.

## S0에서 실측된 것 (추측으로 덮어쓰지 말 것)

`bpf/smoke` 를 유휴 상태 개발 노트북에서 71초 돌린 결과다.

- **`file_open` 호출 빈도: 유휴 초당 5~15건, 명령 실행 버스트 시 초당 400~1,200건.**
  사전 추정치(초당 수천)보다 두 자릿수 낮다. 다만 **유휴 노트북 숫자다** — S1은 반드시 부하 구간(`apt install`·커널 빌드·대형 리포 `git status`)에서 재야 한다.
- **쓰기 의도는 전체 `file_open` 의 4.7%** (123 / 2,598).
  → **`f_mode & FMODE_WRITE` 비트 테스트 하나가 95%를 걸러낸다.** 판정 함수의 앞문은 이 한 줄이어야 한다. 훅은 100% 불리지만 맵 조회까지 가는 건 5%다.
- **`dev` major 0(procfs·sysfs·tmpfs·cgroupfs·pipefs)이 트래픽의 대부분.** 실디스크(`259:x`)는 소수다.
  그렇다고 **superblock 필터로 건너뛰지 않는다** — `/proc/sys/kernel/*` 쓰기와 `/sys/fs/cgroup` 조작은 정확히 통제 대상이다. 쓰기 게이트 하나로 충분하다.
- **`sched_process_fork` 는 71초에 51건.** 2차 방어선은 사실상 공짜다.
- **cgroup id가 세션·서비스마다 다르게 찍힌다** (systemd 자신은 `pid=1`). §04의 1차 태그가 실물로 성립한다.

## S1에서 실측된 것 (2026-09-07, 커널 6.8.0 · i7-1165G7 8코어)

`bench/overhead` 3차 실행(`out/20260907-200813`), 10회 × 6패스 교차, **티어 E 포함.**
전체 실험 경위는 `docs/experiments.md` 에 있다.

**S1 통과. 최악 조건에서 1% 미만이다.** 기준은 "한 자릿수 %" 였다.

- **근거는 마이크로다. 매크로가 아니다.** 쓰기 포화 워크로드(`w_untar`, 98.6%)에서
  훅 1회당 판정 비용 **77ns**(B 차감), 호출 40,851건 → 3.16ms → A(875ms) 대비
  **0.36%**. LSM 부착 비용을 얹어도 **0.4~0.5%** 다.
- **매크로는 상한으로만 읽는다.** 3차에서 네 워크로드 모두 「노이즈 이하」다
  (|Δ| < 1.5%). 기계 sd 가 3~4% 인데 찾는 신호가 0.4% 라 **분해될 수 없다.**
  0.4% 를 유의하게 잡으려면 n≈900 런이 필요하다 — 재실행으로 풀 문제가 아니다.
- **~~"+2.0% 최악조건"(2차) 은 철회한다. 물리적으로 불가능한 값이었다.**
  +2.0% of 1.090s = 22ms ÷ 40,851 = **539ns/call** 인데, **같은 실행의** 커널 안
  실측은 **177ns/call** 이다 — 3.0배 어긋난다. (3차의 77ns 와 비교하면 안 된다.
  2차는 기계가 베이스 클럭이라 훅 자체도 느렸다. **실행을 섞어 비교하지 말 것.**)
  2차의 +2.0% 도 3차의 -0.5% 도 둘 다 훅을 잰 값이 아니다.
  실행별 예상 Δ 는 2차 0.66% · 3차 0.36% — **클럭 상태에 따라 0.4~0.7%,
  어느 쪽이든 1% 미만이다.**
- **§13 의 비용 주장은 거짓이다 — E ≈ D.** `w_untar` 에서 E 가 D 비용의 **92%**
  (71 / 77ns) 를 낸다. 빠져나가는 건 맞다(`tag_hit=0 tag_miss=40,239`) —
  **그게 싸지 않을 뿐이다.** 비용 분해: 쓰기 확인 21ns → **cgroup id + 1차 조회
  +51ns** → 2차 조회 + 만료 비교 +6ns. `bpf_get_current_cgroup_id()` 가
  `task→cgroups→dfl_cgrp→kn→id` 를 타야 하고, **영장이 있든 없든 거기까진 똑같이 간다.**
  → **"무영장 세션이 많으니 실서버는 더 싸다"는 논거를 쓰지 말 것.** 최악값(D)으로 잡는다.
  방향이 보수적이라 기존 추정치가 나빠지지는 않는다. 꼬리에서는 D 가 더 비싸다
  (p99.9 E 128-255 vs D 256-511) — 2차 조회 비용은 p50 이 아니라 tail 에만 나타난다.
- **앞문 설계는 유지된다.** 읽기 지배 워크로드(`w_find`, 쓰기 0.0%, 초당 27만 open)
  에서 C·E·D 가 전부 같다(6~12ns). cgroup 조회가 공짜인 게 아니라
  **거기까지 가는 호출이 없다.** `f_mode & FMODE_WRITE` 앞문의 직접 증거다.
- **태그 조회가 정확하다.** D 는 `tag_miss=0`, `tag_hit` 이 쓰기 건수와 일치
  (`w_untar`: 40,237). E 는 `tag_hit=0`, 전건 miss.
- **dev major 는 워크로드의 성질이지 훅의 성질이 아니다.** 여기서는 259(nvme)가
  98~99%, major 0 은 1% 남짓 — **S0 의 유휴 프로파일(major 0 우세)과 정반대다.**
  둘 다 참이고, 그래서 superblock 필터는 여전히 넣지 않는다 (§15).
- **`w_git` 은 3차에서도 측정 무효다.** 프로세스 기동 시간이 지배적이라 훅 비용을
  잴 그릇이 못 된다. 마이크로로만 읽는다.
- **기계가 실행 중 주파수를 오르내렸다.** `w_find` 패스별 평균이 0.53 / 0.85 두
  모드로 갈린다(모든 티어에서 동일). 비율 1.60 ≈ 터보 4.7GHz / 베이스 2.8GHz.
  앞으로의 실행은 `cpupower frequency-set -g performance` 로 고정한다.
  **단, 그것만으로는 부족하다(6차)** — 고정해도 두 모드가 남았다. 노트북 CPU 의
  터보 예산 · 발열 제한은 거버너와 별개다.

**읽기 감시(`read_watch_paths`, §15) — 4~6차 (2026-09-22~23, 커널 -139). 닫힘.**
D 위에 읽기 감시를 얹는 티어 R · I · I2 를 쟀다. 읽기 지배 `w_find` 에서
**R > I > I2 순위가 두 실행 모두 같다** → I2(inode 먼저 + 직접 load)로 넣는다.
크기는 기계 상태에 따라 흔들린다 — I2 는 D 대비 +0.57~1.78%, D 를 합친 최악
**≈ 0.9~2.0%**. 한 자릿수 % 는 넉넉히 통과한다. ~~1% 미만~~(5차 한 번으로 적었다가 6차에서 정정).
**이 하네스의 ns 는 같은 실행 안의 순위로만 읽는다** — 마이크로 단계가 셔플되지 않아
슬롯마다 기계 속도가 다르다(알려진 한계, `docs/experiments.md` S1 6차).
- **`BPF_CORE_READ` 는 포인터 한 단계마다 헬퍼를 부른다.** I 비용의 70%(58/82ns)가
  그것이었다. **제품 판정 함수는 BTF 포인터를 직접 따라간다.** 앞문 `f_mode` 도 같은
  방식으로 싸질 수 있으나 **미측정이다.**
- 4차의 "조회 순서는 무관"은 **철회** — 노이즈(±32ns)에 묻힌 판정이었다. 5 · 6차 모두
  R > I. 같은 I 가 4차 147 · 5차 82 · 6차 154ns — **실행을 섞지 말 것.**
- **B 를 빼면 검산이 빈다.** 4차는 B 없이 돌아 매크로 인공물이 "유의"로 남았고, 5차는
  같은 종류(D +27.5%)를 검산이 "77배, 훅이 낼 수 없는 값"으로 잡았다.

**방법론 — 이게 S1 이 남긴 가장 중요한 것이다.**
µs 이하 훅의 비용은 벽시계로 재는 게 아니다. **커널 안에서 1회 비용을 재고
호출수를 곱한다.** 매크로는 그 계산이 자릿수로 어긋나지 않는지 확인하는 용도로만
남는다. `report.py` 의 「검산: 마이크로 → 매크로」 절이 이걸 자동으로 대조하고,
훅이 낼 수 없는 매크로 값이 나오면 경고한다 — 사람이 매번 눈치채야 하는 상태로
두지 않는다.

## S3에서 실측된 것 (2026-09-08, 커널 6.8.0 · OpenSSH 9.6p1) — 통과

`bench/pamtiming` 3단계, **`/etc/pam.d/sshd` 에서 `ssh localhost` 11회**
(`out/20260908-230244`). 세션 14~24. **§11 T1 의 가정이 참이다.**

- **`present_t0` 11/11 · `match` 11/11 · `waited_us=0` 전건.**
  session 단계에 들어온 순간 `session-N.scope` 가 **이미 확정돼 있다.**
  폴링이 한 번도 안 돌았다 — **태깅 공백이 없다.**
- **설계가 안 바뀐다.** `pam_warrant.so` 는 `XDG_SESSION_ID` → 경로 조립 →
  `stat` 로 끝난다. **warrantd 의 cgroup 트리 순회도, logind D-Bus 구독도
  필요 없다.** 실패했으면 `pam/` 와 `agent/internal/pamsock` 이 뒤집혔을 자리다.
- **`/proc/self/cgroup` 도 같은 값을 준다** (`match=yes` 전건). 호출 시점에
  scope 이관까지 끝나 있다. 그래도 제품은 §11 T1 대로 `XDG_SESSION_ID` 경로를
  쓴다 — 두 값이 같은 건 확인된 사실이지 보장이 아니다.
- **(§11 T4) `close_session` 에서 scope 가 아직 살아 있다 (11/11).**
  `cgroup_warrant` 엔트리 정리를 `close_session` 에 걸 수 있다. 다만 `nohup`
  으로 살아남은 프로세스가 있으므로 정리 정책은 별도 판단이다.
- **★ `XDG_SESSION_ID` 는 재사용된다. cgroup id 는 아니다.**
  앞선 `test-detached` 실행에서 3회 모두 `session-4.scope` 인데 cgid 가
  **13299 · 13408 · 13517** 로 전부 달랐다. 같은 세션 번호가 서로 다른 cgroup 을
  가리켰다 — **영장을 세션 번호에 걸면 다음 세션이 남의 영장을 물려받는다.**
  §11 T1 이 cgroup id 를 키로 쓰는 설계의 직접 증거다. 재려던 게 아니라
  로그에 딸려 나온 수확이다.
- **여기까지 오는 데 두 번 헛돌았다.** `pam_systemd.so` 는 **호출자가 이미
  사용자 세션 안이면 세션 생성을 건너뛴다.** 데스크톱 터미널에서 돌린 1·2단계
  (`pamtester`·`su`)는 8건 전부 `xdg_session_id=-` 로 판정 불가였다.
  **`pam_systemd.so` 가 스택에 있는 것과 그게 실제로 세션을 만드는 것은 다르다.**
  `systemd-run --slice=system.slice` 로 세션 밖에서 부르면 만들어진다.
- **부수 확인:** 기존 세션 안에서 `su` 를 하면 새 세션이 안 생기고 cgroup 이
  그대로다. §04 가 원하는 동작이고, **S2 의 `su` → `cg_tag=1` 을 PAM 층에서
  독립적으로 본 것**이다.

## S2에서 실측된 것 (2026-09-03, 커널 6.8.0)

`bench/bypass` 17케이스 — **8 통과 · 9 skip · 0 실패.** §04 표가 이 커널에서 참이다.

- **표식이 `sudo`·`su`·`nohup`·`setsid`·`&` 를 전부 통과한다** (`cg_tag=1 task_tag=1`).
  uid가 65534로 바뀌어도 유지된다. 기획서 §04: *"떨어지면 그냥 또 하나의 셸 래퍼다."*
  안 떨어졌다. **제품의 성립 조건이 실물로 확인됐다.**
- **`systemd-run --scope` 가 `cg_tag=0 task_tag=1` 로 나온다.**
  cgroup은 갈아탔는데 fork 체인이 살아 표식이 남았다 — **2차 방어선의 존재 이유가
  실측으로 증명된 것**이고, 이게 S2에서 가장 값진 한 줄이다.
  1차만 있었으면 여기서 뚫렸다.
- **`systemd-run`(기본)·`docker exec` 는 `cg_tag=0 task_tag=0`.**
  문서가 인정한 위임 경로가 문서대로 끊긴다. 예상된 결과이고, 이것도 검증된 사실이다.
- **아직 진짜 세션이 아니다.** bats 자신의 cgroup을 태그했다. `session-N.scope` 와
  성질은 같지만, **S3(PAM 타이밍) 뒤에 진짜 세션으로 재확인해야 한다.**
  그때 `helpers.bash` 만 갈아끼우고 케이스는 손대지 않는다.
- 위임 경로의 진짜 방어선(실행 화이트리스트 · AF_UNIX 차단 · spool 차단)은
  셋 다 미구현이라 skip이다. **"끊긴다"는 검증했고 "막는다"는 아직이다** — 이 구분을
  흐리지 말 것.

## 아키텍처 — 세 평면 (§10)

판정 시점에 유저 공간으로 올라오는 왕복이 **하나도 없다**는 게 설계의 핵심이다.
중앙은 발급하고, 노드 유저 공간은 맵에 옮겨 적고, **커널은 그 맵만 보고 판정한다.**

```
중앙 (server/)                 노드 유저 공간 (agent/ pam/)        커널 (bpf/)
─────────────────              ──────────────────────────        ─────────────
발급 · 승인 · 신원                warrantd                          BPF 맵
Ed25519 서명                      · 정책 → (dev,ino) 컴파일           cgroup_warrant
      │                          · 절대시각 → boot 기준 변환          task_warrant
      │  gRPC push               · ringbuf 소비                      warrants
      └─────────────────────▶    · bbolt 로컬 캐시                    rule_{exec,write,net}
                                      │                                   ▲
      ◀─────────────────────         맵 쓰기 ──────────────────────────────┘
         감사 이벤트 스트림             ▲                                   │
                                       │ 유닉스 소켓                      판정
                                  pam_warrant.so                          │
                                  (세션 → cgroup id)              세션 프로세스
```

**계층 경계에서 무엇이 변환되는가** — 이게 세 계층을 같이 안 보면 안 보이는 부분이다.

| 경계 | 들어가는 것 | 나오는 것 | 변환 주체 |
|---|---|---|---|
| 중앙 → warrantd | 경로 문자열 · CIDR | `(dev, ino)` · LPM 엔트리 | warrantd `internal/policy` |
| 중앙 → warrantd | 절대시각 (Unix ns) | `expires_ns` (노드 boot 기준) | warrantd. **여기서만 한다** |
| PAM → warrantd | `XDG_SESSION_ID` | cgroup id | `pam_warrant.so` (S3 에서 방법 확정) |
| warrantd → 커널 | `Warrant` 메시지 | `struct warrant` 맵 값 | `internal/bpfmap` |

세 계층의 구조체가 전부 `proto/warrant.proto` 에서 나온다. 커널 구조체와 서버
엔티티가 어긋나면 디버깅이 지옥이 되므로 **필드는 예외 없이 거기부터 고친다.**

## 핵심 개념 (여기서 벗어나면 제품이 아니다)

- **영장은 cgroup에 붙는다.** systemd-logind가 만드는 `session-N.scope` 의 cgroup id에 걸어서 `sudo`·`su` 로 uid가 바뀌어도 표식이 유지된다. 2차 방어선으로 `sched_process_fork` 에서 부모 태그를 자식 task_storage에 복사한다. 이 두 겹이 성립하지 않으면 제품 전체가 성립하지 않는다 (§04).
- **만료가 세션 안에서 발효된다.** LSM 훅이 매 판정마다 `bpf_ktime_get_boot_ns()` 와 `expires_ns` 를 비교한다. 유저 공간 왕복도, 타이머도, 프로세스 순회도 없다. 취소는 `revoked` 1바이트 (§05, §12).
- **판정 시점에 유저 공간으로 올라가지 않는다.** 중앙 → warrantd → BPF 맵에서 흐름이 끝나고, 그 뒤로는 커널이 혼자 판정한다. 중앙이 끊겨도, warrantd가 죽어도 이미 발급된 영장의 집행은 계속된다 (§10, §17).
- **읽기는 통제하지 않는다.** `file_open` 오버헤드 때문에 쓰기·삭제·이름변경만 판정하고, 그 대가는 아웃바운드 전면 차단으로 메운다 (§15).
- **경로가 아니라 `(dev, ino)` 쌍으로 식별한다.** 허용 목록은 파일 inode로 충분하지만 **금지 목록은 반드시 디렉터리 inode** 로 걸어야 한다 — 파일 inode 금지는 `mv` 후 재생성으로 뚫린다 (§15).
- **감사 모드와 강제 모드가 판정 함수를 공유한다.** `static __always_inline` 판정 함수 하나를 `lsm/*` 과 `kprobe/security_*` 이 각각 호출한다. "감사에서는 안 걸렸는데 강제로 켜니 막히더라"가 구조적으로 생기지 않아야 한다 (§15).
- **fail 방향이 비대칭이다.** 강제 경로(커널)는 단단하게 실패하고, 발급 경로(PAM·중앙)는 느슨하게 실패한다. PAM이 warrantd에 못 붙으면 **로그인을 허용**하고 무영장 세션으로 기록·경보한다. 여기서 fail-close를 택하면 장애 때 아무도 못 들어간다 (§17).

## 기술 스택 (버전 고정 — 임의로 올리지 말 것)

| 계층 | 언어 | 핵심 의존성 |
|---|---|---|
| BPF 프로그램 | C | libbpf · vmlinux.h · clang/LLVM 18+ · CO-RE |
| 노드 에이전트 `warrantd` | Go 1.25+ | cilium/ebpf v0.22 · bpf2go · grpc-go · bbolt · x/sys/unix |
| PAM 모듈 | C | libpam-dev |
| 중앙 서버 | Java 25 (LTS) | Spring Boot 4.1.1 · Security(OIDC) · Data JPA · Flyway · `spring-boot-starter-grpc-server` |
| DB | — | PostgreSQL 18 (감사 이벤트는 선언적 파티셔닝) |
| 대시보드 | TypeScript | React 19 · Vite — 또는 Grafana로 대체 |

중앙 서버는 Spring Web MVC + 가상 스레드(WebFlux 불필요) · Testcontainers + JUnit 5 · Ed25519는 JDK 내장.

**`server/` 빌드는 2026-09-01 에 실증됐다.** 52클래스가 Java 25(class major 69)로
컴파일되고 `bootJar` 가 나온다. 고정한 버전이 실제 산출물과 일치한다 —
protobuf-java 4.35.1 · grpc 1.83.1 · spring-webmvc 7.0.9 · flyway 12.4.0 ·
spring-security-oauth2 7.1.1 · hibernate 7.4.5. **Boot 버전을 올릴 때 이 목록을
다시 확인할 것** (`build.gradle` 의 `ext` 두 줄이 BOM 과 어긋나면 조용히 깨진다).

`settings.gradle` 의 **foojay toolchain 리졸버를 지우지 말 것.** 없으면 JDK 25 가
설치되지 않은 기계에서 `No matching toolchains found` 로 빌드가 시작조차 못 한다.
맥북(편집)과 서브 PC(빌드)의 JDK 를 손으로 맞추지 않기 위한 장치다.

테스트는 아직 0개다. Gradle 9 는 그걸 빌드 실패로 다루므로
`failOnNoDiscoveredTests = false` 로 꺼 뒀다 — `WarrantServerApplicationTests` 주석에
적힌 케이스 8개가 채워지는 순간 그 줄을 지운다. 가짜 통과 테스트로 초록을
만들지 말 것.

**Spring Boot 4는 스타터 이름이 Boot 3과 다르다.** `spring-boot-starter-web` → `-webmvc`, oauth2 스타터 → `spring-boot-starter-security-oauth2-*`, Flyway는 전용 스타터, gRPC는 Boot가 spring-grpc를 흡수해 `spring-boot-starter-grpc-server`가 됐다 (`org.springframework.grpc` 스타터는 1.0.3에서 멈췄으니 그 BOM을 import하지 말 것). Boot 3 예제를 그대로 옮기면 "Could not find ..."로 실패한다.

언어가 넷인 것은 제약이다: BPF는 C만 되고, PAM은 sshd 주소 공간에 dlopen되므로 Go 런타임을 넣을 수 없고, 중앙은 Java로 정해져 있다. Rust(aya)가 아니라 Go인 이유는 성능이 아니라 **막혔을 때 검색으로 풀리는가**다.

## 개발 환경

**물리 서브 PC 한 대**에서 개발한다. Vagrant VM이 아니다 — BPF LSM은 부팅 파라미터와 커널 BTF에 묶여 있어서, VM 층을 끼우면 "안 되는 게 커널 문제인지 가상화 문제인지"를 매번 의심하게 된다.

| | |
|---|---|
| 서브 PC | Ubuntu 24.04.4 LTS · 커널 6.8.0 — 기획서 §02의 개발 기준과 일치 |
| 편집 | macOS (이 리포) |
| 빌드·실행·측정 | 서브 PC |
| 동기화 | GitHub `session-warrant/session-warrant` · 브랜치 `main` |

검증 대상: 커널 7.0(Ubuntu 26.04) · Rocky 9 호환. 3노드 구성은 중앙 서버가 붙는 시점에 꺼낸다.

명령은 아래 「명령」 절에 모아 뒀다.

`cat /sys/kernel/security/lsm` 출력에 `bpf` 가 없으면 강제 모드는 한 줄도 못 짠다. `enable-bpf-lsm.sh` 는 **지금 떠 있는 목록을 읽어 거기에 `,bpf` 만 덧붙인다** — `lsm=bpf` 만 단독으로 넣으면 AppArmor가 빠지면서 부팅이 깨질 수 있다.

## 명령

계층마다 도구가 다르다. **BPF·bench 는 서브 PC(Linux, root)에서만 돈다.**
`server/` 와 `web/` 는 맥북에서도 된다.

### 환경 확인 — 막히면 여기부터

```sh
./deploy/bootstrap.sh              # 커널·BTF·lsm=bpf·툴체인. 표로 찍는다
./deploy/bootstrap.sh --install    # 부족한 것 설치 (22.04/24.04 양쪽)
sudo ./deploy/enable-bpf-lsm.sh    # lsm= 에 bpf 추가. 재부팅 필요
```

`make check` 가 `bpf/` 와 `bench/*` 전부에 있다. **BPF 쪽이 안 되면 그 디렉터리의
`make check` 를 먼저 돌린다** — 없는 도구와 설치 명령을 같이 찍어준다.

### BPF

```sh
make -C bpf                 # smoke.bpf.o + 로더. vmlinux.h 는 여기서 생성(gitignore)
sudo ./bpf/smoke            # S0 스모크
make -C bpf check           # BTF · lsm · clang · bpftool
```

### 벤치 — 훅을 붙일 때마다 돌린다

```sh
# S1 오버헤드 (8티어 × 워크로드 4종. R·I·I2 는 읽기 감시)
cd bench/overhead && make && ./fixture.sh
sudo ./run.sh                                  # 기본 5회 × 4패스
sudo ./run.sh --passes 6 --runs 10             # 정식
sudo ./run.sh --workloads w_untar,w_find       # 일부만
sudo ./run.sh --tiers a,b,d,r,i,i2             # 읽기 감시 티어만. B 는 검산 기준이라 빼지 말 것
python3 report.py out/<타임스탬프>              # 재집계

# S2 §04 우회 표 (bats)
cd bench/bypass && make && sudo make test      # 17케이스 → out/<ts>.txt
sudo bats -f '§04-3' tag_propagation.bats      # ← 케이스 하나만
sudo bats tag_propagation.bats                 # 한 파일만

# S3 PAM 타이밍 — 3단계 사다리를 건너뛰지 말 것
cd bench/pamtiming && make && sudo make install
sudo make test                                 # 1단계. 위험 0
sudo make test-detached                        # 1.5단계. 여기서 판정이 나온다
sudo I_HAVE_CONSOLE=1 make enable-sshd         # 3단계. 콘솔 확보 후에만
sudo make collect && sudo make disable         # 결과 수집 + 원복

# S4 inode 안정성
cd bench/inode && make && sudo make test
sudo make test-apt                             # 실제 패키지 재설치 포함
```

측정 결과는 각 `out/` 에 들어가고 **커밋 대상이다.** 서브 PC 에서 재고 맥북에서
읽는 유일한 통로다. `run.sh`·`make test` 가 끝에 `git add` 명령을 찍어준다.

### 서버

```sh
cd server
./gradlew build                    # 컴파일 + 테스트 + bootJar
./gradlew generateProto            # proto/*.proto → Java (protobuf + grpc)
./gradlew test --tests '*WarrantServerApplicationTests'    # ← 테스트 하나만
```

**`bootRun` 은 아직 뜨지 않는다.** datasource·bean 이 전부 주석이라 컴파일과
`bootJar` 까지만 검증돼 있다. 테스트도 0개다 (`failOnNoDiscoveredTests = false`).

`proto/` 를 고치면 `server/build.gradle` 의 `srcDir '../proto'` 를 통해 자동으로
다시 생성된다 — **`.proto` 수정 뒤 `./gradlew generateProto compileJava` 로
세 언어 중 최소한 Java 쪽은 깨지지 않았는지 확인한다.** Go·C 생성물은 아직 없다.

### 웹 (범위 밖, 동결)

```sh
cd web && npm install
npm run build                      # tsc -b && vite build
npm run build:single               # 의존성 없는 단일 HTML (공유용)
```

## 리포지토리 구조 (모노레포)

```
proto/    protobuf 스키마 — 팀 간 계약. 스파이크 뒤에 확정한다
bpf/      C · BPF 프로그램 (vmlinux.h는 gitignore, 커밋하지 않는다)
agent/    Go · warrantd
          cmd/warrantd/ · internal/{loader,bpfmap,pamsock,policy,ringbuf,upstream,store}/ · bpf/(bpf2go 생성물, 커밋한다)
pam/      C · pam_warrant.so (200줄 이내로 유지)
server/   Java · Spring Boot  ← 골격 있음
web/      대시보드 — 이번 학기 범위 밖. Grafana 로 대체, 목 데이터 상태로 동결
deploy/   bootstrap.sh · enable-bpf-lsm.sh · systemd/ · ansible/
bench/    bypass/(§04 우회) · overhead/(훅별 실측) · pamtiming/(PAM 타이밍) · inode/(inode 안정성)
```

## 3인 분담 (2026-09-09 확정)

기술 스택 문서 §10 의 A·B·C 틀을 따르되, **프론트(`web/`)는 범위에서 뺀다.**
화면은 Grafana 가 PostgreSQL 을 직접 읽는 걸로 대체하고, React 화면 4개는 목 데이터
상태로 동결한다. C 가 화면 대신 warrantd 의 유저 공간 절반을 가져간다.

| | 이름 | 담당 | 소유 디렉터리 |
|---|---|---|---|
| **A** | 장지은 | 커널 | `bpf/` · `agent/internal/{loader,bpfmap,ringbuf,policy}` |
| **B** | 김종혁 | 서버·계약 | `proto/` · `server/` · `agent/internal/{upstream,store}` |
| **C** | 김강민 | 노드 통합·검증·운영 | `pam/` · `agent/internal/pamsock` · `agent/cmd/warrantd` · `bench/` · `deploy/` |

**경계는 언어가 아니라 계약이다.** 사람 경계가 계약 경계와 겹치도록 잘랐다.

- **A ↔ B 의 경계는 BPF 맵 레이아웃 하나다.** gRPC 가 아니다. `bpfmap` 패키지는 A 소유이고,
  B 의 `upstream` 은 그 패키지의 함수만 부른다. 맵 값 구조체는 `proto/warrant.proto` 에서 나온다.
- **PAM 과 `pamsock` 은 유닉스 소켓 한 쌍이고 양 끝을 C 가 쓴다.** 와이어 포맷을 문서로
  합의할 필요가 없다. 검증 하네스 `bench/pamtiming` 도 같은 사람 것이다.
- **gRPC 양 끝(서버 · warrantd 클라이언트)을 B 가 쓴다.** B 가 Go 를 못 하면
  `upstream`·`store` 는 C 로 넘기고, 그때는 proto 확정이 더 급해진다.
- **벤치는 커널 담당이 짜지 않는다.** 자기 코드를 자기가 재면 유리한 조건만 재게 된다.

**기계.** BPF 는 서브 PC 한 대에서만 돈다. A 가 기계를 소유한다. C 는 PAM 작업에 물리
콘솔이 필요하므로 시간대를 나누거나 두 번째 박스를 둔다. B 는 기계가 필요 없다.

**인수인계.** 스파이크 S0~S3 와 proto 초안은 김종혁이 혼자 진행했다. 커널 실측 경험이
전부 B 에게 있으므로, 첫 주에 `docs/experiments.md` 와 `bench/` 결과를 A 에게 넘기는
시간을 따로 잡는다.

**통합 마일스톤은 하나다.** 훅 하나(`sched_process_fork` 또는 `bprm_check_security`)
→ warrantd → 서버 → Grafana 패널까지 **"무영장 세션 한 건이 뜬다"를 4주 차에** 만든다.
그 뒤로는 A 가 훅을 하나씩 늘릴 때마다 C 가 bench 로, B 가 서버 테스트로 검증만 한다.
강제 모드는 누구 담당에도 넣지 않는다.

## 작업 규칙

- **BPF 타입 이름에는 예외 없이 접두사를 붙인다** (`warrant_*`). `vmlinux.h` 는 커널의 전체 타입을 통째로 들여오므로 `struct sample` · `event` · `task` · `config` 는 전부 이미 존재한다. 증상은 `error: redefinition of ...` 한 줄 뒤에 따라오는 "no member named" 무더기다 — 첫 줄만 보면 된다.
- **스파이크 전 구간은 감사 모드다.** LSM 훅은 `return 0` 만 한다. 자기보호 6종을 붙이기 전에 `-EPERM` 을 켜면 verifier를 통과한 버그 하나로 자기 박스에서 잠긴다.
- **`proto/warrant.proto` 가 단일 진실 원본이다.** `struct warrant` 의 필드, 서버 엔티티, BPF 맵 값이 모두 같은 `.proto` 에서 나와야 한다. 커널 구조체와 서버 엔티티가 어긋나면 디버깅이 지옥이 된다. 단, **확정은 스파이크 뒤에** — 커널이 뭘 필요로 하는지 모르는 상태에서 확정하면 세 계층이 다 그 위에 붙은 뒤에 고치게 된다.
- **훅은 한 번에 하나씩 붙인다.** 순서: `sched_process_fork` → `bprm_check_security` → `socket_connect` → `file_open` → `inode_{create,unlink,rename,link,symlink}`(5개 한 세트) → 자기보호 6종 → `socket_sendmsg` → `kprobe/security_*` 미러. 훅 하나마다 verifier 통과와 오버헤드를 같이 확인한다.
- **자기 보호 6종은 정책이 아니라 제품이 강제 삽입하는 기본 규칙이다** (`lsm/bpf`, `task_kill`, `sb_umount`, `ptrace_access_check`, `kernel_module_request`, warrantd 자기 파일 쓰기 금지). 영장 작성자가 실수로 열 수 없어야 하고, 하나라도 빠지면 나머지가 무의미하다 (§16).
- **BPF 프로그램과 맵은 bpffs에 pin한다.** warrantd 재시작 중에도 태깅 공백이 생기면 안 된다. systemd 유닛에 `Before=sshd.service` 는 필수다 — 없으면 부팅 직후 세션이 태그 없이 시작된다.
- **PAM 스택에서 `pam_warrant.so` 는 `pam_systemd.so` 뒤에 온다.** 그 전에는 `session-N.scope` 가 아직 없다 — **이건 아직 가정이고 S3 이 그걸 잰다.** `/etc/pam.d/sshd` 를 건드리는 작업은 **물리 콘솔 접근이 가능한 상태에서만** 하고, `bench/pamtiming` 의 3단계(pamtester → su → sshd)를 건너뛰지 않는다.
- **서명은 protobuf 직렬화 바이트에 한다.** JSON 서명은 키 순서·공백 정규화 문제를 만든다. Ed25519는 JDK 내장을 쓴다(BouncyCastle 불필요).
- **`bench/` 는 초기 구조에 넣는다.** §04의 우회 경로 표가 그대로 bats 테스트 케이스다. §18이 인정한 4가지 구멍(만료 전 열어둔 fd, connect 없는 UDP, 데몬 위임, `kubectl exec`)도 **skip 사유를 명시해 실패 테스트로 커밋**한다 — "알고 있으나 막지 못한다"와 "모른다"는 다르게 취급된다.
- **감사 기록은 절제한다.** 차단은 전건 기록, 허용은 `exec`·`connect` 처럼 빈도 낮은 것만. 쓰기 허용까지 다 남기면 ringbuf가 넘친다. 유실 구간은 반드시 명시적으로 기록해 "빈 구간"을 숨기지 않는다 (§13, §14).
- **정책 컴파일러는 실행 허용 목록과 쓰기 허용 목록의 조합을 경고해야 한다.** 예: `systemctl` 실행 허용 + `/etc/systemd/system` 쓰기 허용 = 임의 코드 실행 경로 (§04).
- **`.gitignore` 의 전역 무력화 블록을 지우지 말 것.** 사용자 전역 `~/.gitignore_global` 이 `docs` 와 `*.md` 를 제외한다. 이 리포에서는 그 둘이 1급 산출물이라 리포 `.gitignore` 에서 되살려놨다.

## 표현 주의

- ✗ "모든 명령을 기록합니다" — `cd` 한 번이면 반증된다(셸 빌트인은 exec이 없다).
- ✓ "실행된 모든 프로세스를 사람에게 귀속시켜 기록합니다."
- argv는 1급 증거가 아니다(`exec -a` 로 위조 가능 + BPF 스택 제약으로 잘림). 신뢰 근거는 커널이 실제로 연 바이너리의 inode다 (§14).
- 이 제품은 "root를 없애는 제품"이 아니라 "root가 하는 일에 사유와 기한을 붙이는 제품"이다. 커널 익스플로잇·부팅 경로 장악 앞에서는 무의미하다 (§06).

## 다음 단계 — 스파이크가 먼저다

기획서 §09가 선행 검증 셋을 지목했다: PAM에서 session scope가 확정되는 타이밍 · **`file_open` 훅의 실측 오버헤드** · inode 갱신 추적의 안정성. **이 중 둘째가 가장 위험하므로 PoC는 여기서 시작한다.**

스파이크는 던져버리는 코드다. 남기는 건 `bench/` 의 측정 하네스와 bats 케이스뿐이다.

| | 스파이크 | 판정 기준 | 실패하면 |
|---|---|---|---|
| **S0** ✅ | 환경 — `bootstrap.sh` · `enable-bpf-lsm.sh` · `bpf/smoke` | attach·동작 확인 | — |
| **S1** ✅ | **`file_open` 오버헤드** — 5티어 비교, p99까지 | 한 자릿수 % | — (통과, **1% 미만**) |
| S2 ✅ | 태그 두 겹 — cgroup + fork 전파, §04 표 = bats | 앞 3줄(6건) 초록, 뒤 4줄 '끊김'이 확인됨 | — (통과) |
| S3 ✅ | PAM 타이밍 — `bench/pamtiming` (sshd 11/11) | `present_t0` 전건 yes | — (통과, 태깅 공백 없음) |
| **S4** ← 마지막 | inode 안정성 — `bench/inode` (하네스 완성, 미실행) | inode 가 바뀌는 조작을 fanotify 가 **전부** 잡는다 | fanotify 범위 확대 · 주기적 재stat |

### S1은 3단이 아니라 4단이다

S0에서 쓰기 비중이 4.7%로 나왔으므로, **쓰기 게이트가 독립된 측정 층**이 된다. 3단으로 재면 "훅이 비싼가 판정이 비싼가"가 뭉개진다.

| | 훅 내용 | 재는 것 |
|---|---|---|
| A | 훅 없음 | 기준선 |
| B | `return 0` 만 | LSM 훅 부착 자체의 비용 |
| C | `+ f_mode & FMODE_WRITE` 앞문 | 95%가 여기서 끝난다 |
| D | `+ cgroup 조회 · 맵 2회 · 시간 비교` | 나머지 5%가 내는 비용 |

워크로드는 **부하 구간**이어야 한다 — `apt install --reinstall` · 커널 헤더 빌드 · 대형 리포 `git status` · `find /usr -type f \| xargs -P8 head -c1`. **평균이 아니라 p99를 본다.** 평균 2%인데 p99가 30%면 못 쓴다. dev major 분포도 같이 찍어 "왜 안 걸렀나"를 나중에 설명할 수 있게 남긴다.

### 스파이크 다음 — §09 MVP

감사 모드 2개월 → 영장 없는 접속 탐지 +1개월 → 강제 +2개월. 승인 연동(Slack → 발급)은 병행하며, **이 흐름이 없으면 아무도 안 쓴다.**

감사 모드에서 멈춰도 제품이 미완성이 아니라는 게 이 계획의 성질이다. 제품 검증과 영업 자료가 같은 데이터에서 나온다.
