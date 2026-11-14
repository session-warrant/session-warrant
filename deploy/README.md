# deploy/

노드 프로비저닝 · 부트 파라미터 · systemd 유닛 · Grafana 화면.

## 개발 환경

**Vagrant VM 이 아니라 물리 서브 PC 한 대**에서 개발한다.
BPF LSM 은 부팅 파라미터(`lsm=bpf`)와 커널 BTF 에 묶여 있어서, VM 층을 하나 끼우면
"안 되는 게 커널 문제인지 가상화 문제인지"를 매번 의심하게 된다.

| | |
|---|---|
| 배포판 | Ubuntu 24.04.4 LTS |
| 커널 | 6.8.0 — 기획서 §02 의 개발 기준과 일치 |
| 편집 | macOS (이 리포) |
| 빌드·실행·측정 | 서브 PC |
| 동기화 | GitHub |

3노드 구성(중앙 + 노드 2대)은 **중앙 서버가 붙는 시점**에 다시 꺼낸다.
스파이크(S0~S4) 는 전부 한 대에서 끝난다.

## 스크립트

```sh
./deploy/bootstrap.sh              # 커널·설정·툴체인 확인만. 표로 찍는다
./deploy/bootstrap.sh --install    # 확인 + 부족한 것 설치
sudo ./deploy/enable-bpf-lsm.sh    # lsm= 에 bpf 추가. 재부팅 필요
```

`bootstrap.sh` 는 22.04 / 24.04 양쪽에서 돈다. 22.04 면 clang 18 을 apt.llvm.org 에서 가져온다.

## `lsm=bpf` — 가장 먼저 확인할 것

```sh
cat /sys/kernel/security/lsm   # 출력에 bpf 가 없으면 강제 모드는 한 줄도 못 짠다
```

`enable-bpf-lsm.sh` 는 **지금 떠 있는 목록을 읽어 거기에 `,bpf` 만 덧붙인다.**
`lsm=bpf` 만 단독으로 넣으면 AppArmor 가 빠지면서 부팅이 깨질 수 있다 — 커널이 스스로
알려준 목록이 가장 안전한 원본이다. 원본 `grub` 은 타임스탬프를 붙여 백업한다.

부팅이 깨지면 GRUB 메뉴에서 `e` 를 눌러 `lsm=...` 을 지우고 부팅한 뒤 백업을 되돌린다.

## systemd (`systemd/`)

```sh
make -C bpf warrant.bpf.o && (cd agent && go build -o ../.cache/bin/warrantd ./cmd/warrantd)
sudo deploy/systemd/install.sh -upstream 중앙:9090     # 설치 · enable --now. 인자는 /etc/default/warrantd 로
sudo deploy/systemd/install.sh --uninstall             # 제거. pin 은 남긴다
```

`warrantd.service` 하나다. warrantd 가 기동할 때 `warrant.bpf.o` 를 직접 올려(`internal/loader`) 맵은
`/sys/fs/bpf/warrant`, 링크는 `/sys/fs/bpf/warrant/links` 에 pin 한다. `Type=notify` — PAM 소켓을 연 뒤
`READY=1` 을 보낸다. `Before=ssh.service sshd.service`, `/run/warrantd` 0700, `Restart=always`.
`install.sh` 는 bpftool 로 올리던 옛 설치(`warrant-bpf.service` · `warrant-progs`)가 있으면 먼저 지운다 —
남겨 두면 모든 훅에 프로그램이 두 벌 붙는다.

- **순서가 제품의 조건이다.** sshd 가 PAM 소켓보다 먼저 뜨면 그 사이 세션은 태그 없이 시작된다.
  `Type=simple` 이면 프로세스가 뜨자마자 started 가 되므로 notify 여야 한다.
  Ubuntu 24.04 는 `ssh.socket`(Accept=no)이 `ssh.service` 를 깨운다. 접속은 sshd 가 뜰 때까지 소켓에서 대기하므로
  `Before=ssh.service` 면 충분하다.
- **`Before=ssh.socket` 을 넣지 말 것 — 부팅이 깨진다.** ssh.socket 은 sockets.target → basic.target 보다 먼저이고,
  이 서비스는 기본 의존성으로 basic.target 뒤라 순환이 생긴다. systemd 는 순환을 끊으려고 작업 하나를 **아무거나**
  버린다. 2026-10-24 에 한 번은 sockets.target 을 버려 우연히 통과했고, 다음 부팅에서는 ssh.socket 을 버려
  sshd 가 안 떠서 VM 에 못 들어갔다(Lima provision 스크립트로 복구). **유닛 순서를 바꾸면 재부팅한 뒤
  `journalctl -b | grep -i "ordering cycle"` 이 비어 있는지 반드시 본다** — 서비스가 떴다는 것만으로는 모른다.
- **pin 은 아무도 지우지 않는다.** warrantd 재시작 · 크래시에도 맵(=태그)과 링크가 그대로다 — 재시작한 warrantd 는
  pin 을 집어 들 뿐 새로 붙이지 않는다(2026-11-01 VM: 재시작 · `kill -9` 전후 맵 id · 링크 id 동일, 훅 15개 중복 없음).
  비우는 건 재부팅뿐이다.
- **그래서 새 `warrant.bpf.o` 는 재부팅해야 적용된다.** 재시작만 하면 pin 된 링크가 잡고 있는 옛 프로그램이 계속 돈다.
  맵 구조가 바뀐 오브젝트는 옛 pin 과 맞지 않아 warrantd 가 뜨지 못한다. 역시 재부팅이 답이다.
- **부팅 순서 실측(2026-11-01, Lima VM 재부팅, 순환 경고 0줄):**
  `ssh.socket` Listening 08.583 → warrantd 훅 15개 10.358 → `warrantd` Started(READY) 10.359 →
  `ssh.service` Started 10.399. 소켓은 먼저 열려도 sshd 는 PAM 소켓이 준비된 뒤에 뜬다.
  중앙이 꺼져 있어도 warrantd 는 뜨고 업로드만 재시도한다.
- **BPF 를 못 올리면 warrantd 는 안 뜨고, 로그인은 된다**(§17). ssh 쪽에 `Requires=` 를 걸지 않았다. 오브젝트를 치운 채
  부팅해 ssh 로 들어가는 것을 확인했다(2026-11-01). warrantd 는 5번 재시도한 뒤 `failed` 로 멈추고, 원인을 고친 뒤
  `sudo systemctl reset-failed warrantd && sudo systemctl restart warrantd` 를 해야 돈다.
  **그동안 태깅도 무영장 기록도 없다** — `warrantd` 실패는 경보 대상이지만 아직 경보가 없다. 중앙은 `node.last_seen_at` 으로도
  알 수 없다(하트비트 전).
- **실제 sshd 로 시험하는 법(2026-10-24 확인).** 원복 타이머를 먼저 건다 — 잘못돼서 못 들어가도 10분 뒤 저절로 빠진다.
  ```sh
  sudo systemd-run --unit=pam-deadman --on-active=10min /usr/bin/make -C $PWD/pam disable
  sudo I_CAN_RECOVER=1 make -C pam enable-sshd TEST_SOCK=/run/warrantd/pam.sock
  # 맥에서. Lima 의 다중화 연결은 새 PAM 세션을 열지 않는다
  ssh -F ~/.lima/sw/ssh.config -o ControlPath=none -o ControlMaster=no lima-sw true
  sudo make -C pam disable && sudo systemctl stop pam-deadman.timer
  ```
  `ExposeAuthInfo` 는 켜지 않아도 된다 — `SSH_AUTH_INFO_0` 은 꺼진 채로 open_session 에 와서 키 지문이 남는다.
- pin 경로를 시험 하네스(`bpf/wtest.sh` · `warrantctl` 의 `wtest` · `wmaps`)와 다르게 써서 맵이 섞이지 않는다. 다만 훅은 커널 전체에 붙는다 — 하네스를 돌리면 프로그램이 한 벌 더 매달리니, 측정(`bench/`)할 때는 `install.sh --uninstall` 뒤 재부팅한다.

### 로컬 영장 (`/etc/warrantd/warrants.json`)

중앙 없이 시험할 때 쓰는 입구다. 서명이 없어서 중앙 발급이 서면 없앤다. 형식은 `proto/warrant.proto` 의 `Warrant` 를 JSON 배열로 — 예시는
`systemd/warrants.example.json`. warrantd 가 **시작할 때 한 번** 읽는다. 고친 뒤에는 `sudo systemctl restart warrantd`.

- 영장을 하나라도 설치하면 `active_flag` 를 켠다. 끄는 건 시작할 때뿐이다 — 파일 영장이 없고 중앙 구독도 안 할 때.
  시작 로그 `warrants: N installed from file, subscribing=…` 로 확인한다.
- 세션은 **계정(`login_account`) + 키 지문(`ssh_key_fingerprints`)** 이 둘 다 맞아야 붙는다. 계정은 맞는데 키가 다르면
  `KEY_MISMATCH`, 키가 없으면 `NO_KEY` 무영장으로 기록된다. 여럿이 맞으면 늦게 끝나는 영장.
- 거부하고 건너뛰는 것: `target_hosts` 에 이 노드 hostname 이 없음 · 만료 없음 · `MODE_ENFORCE` · `break_glass`.
  정책 경로가 없어도 그 영장만 건너뛴다. 파일이 깨져도 warrantd 는 영장 없이 뜬다(§17).
- 파일에서 지운 영장은 맵에 남는다(이미 붙은 세션은 계속 그 영장). 지우려면 `"revoked": true` 로 남겨 두거나 재부팅한다.
- `/etc/warrantd` 는 자기보호 쓰기 금지 디렉터리(`policy.DefaultDenyWrite`)라 영장 세션 안에서는 이 파일을 못 고친다.
- **2026-11-03 VM 확인:** 맞는 세션 → `warrant=101` 태그, 허용 밖 실행 · 쓰기 → `EXEC`/`WRITE DRY-DENY`, 허용 쓰기는 기록 없음,
  남의 키 → `KEY_MISMATCH`, 다른 계정 → `NO_WARRANT`, CLOSE 뒤 `cgroup_warrant` 비어 있음, 영장 없는 프로세스 기록 0건.
  PAM 은 `systemd-run --scope` 에 OPEN 한 줄을 직접 보내 흉내 냈다 — 실제 sshd 로그인으로는 아직 안 해 봤다.

### 중앙 영장 (`-upstream` + `/etc/warrantd/keys/`)

`-upstream` 이 있고 `-trust-keys`(기본 `/etc/warrantd/keys`) 에 `<key_id>.pem` 이 하나라도 있으면 warrantd 가
`WarrantPushService.Subscribe` 로 영장을 받는다. 키가 없으면 구독하지 않는다 — 검증할 수 없는 영장은 받지 않는다.
키 파일은 Ed25519 공개키의 PKIX(`PUBLIC KEY`) PEM 이고, JDK `PublicKey.getEncoded()` 를 PEM 으로 감싸면 그대로 맞는다.

- 받은 바이트 그대로 서명을 검증하고, 로컬 파일과 같은 검사(대상 호스트 · 만료 · `ENFORCE` · `break_glass`)를 거쳐 같은 순서로 맵에 넣는다.
- 같은 영장은 **revision 이 올라갈 때만** 바뀐다. 연장 · 취소는 새 revision 으로 온다 — 취소는 열린 세션에도 바로 먹는다.
- 같은 `policy_id` 에 다른 규칙이 오면 거부한다(정책 id 는 재사용하지 않는다).
- 스트림마다 서버가 활성 집합 → `ResyncComplete` 를 보낸다. 집합에서 빠진 중앙 영장은 **지우지 않고 취소**한다 — 지우면 이미 붙은
  세션이 「관리 대상 아님」으로 풀린다. 로컬 파일 영장은 건드리지 않는다.
- 검증된 수가 서버가 말한 수보다 적으면 Resync 를 건너뛰고 `upstream: RESYNC SKIPPED …` 를 남긴다. 거의 언제나 키 문제다 —
  서버가 키를 바꿨는데 이 노드의 `/etc/warrantd/keys/` 에 새 키가 없다. 그동안 새 발급은 거부되고 기존 영장은 만료까지 간다.
- bbolt 캐시가 아직 없다. 재시작하면 warrantd 는 이전에 받은 영장을 모르고, 맵에 pin 된 값만 남는다. 다음 resync 가 다시 채우지만,
  **warrantd 가 꺼져 있는 동안 서버에서 취소된 영장은 맵에서 만료될 때까지 살아 있다.** `store` 가 서야 닫힌다.
- **2026-11-08 진짜 서버로 확인:** `SPRING_PROFILES_ACTIVE=dev ./gradlew bootRun` → `GET /api/signing-key` 를
  `/etc/warrantd/keys/central.pem` 으로 → `-upstream host.lima.internal:9090` → curl 로 발급하자 0.1초 뒤 `installed 1 rev=1` →
  세션 태그 · 허용 밖 쓰기 `DRY-DENY` → 세션이 열린 채 `DELETE /api/warrants/{id}` → `rev=2 revoked=true` → 같은 세션의 실행 · 쓰기
  전부 `DRY-DENY` → 새 세션 `NO_WARRANT`. 발급 API 는 `server/README.md` 「영장 발급」.

### 노드 인증서 — mTLS (`pki/pki.sh`)

노드 ↔ 중앙 gRPC 는 mTLS 다. 중앙은 **사내 CA 가 서명한 노드 인증서로만** 노드를 받고, 노드 신원은 그 인증서의 sha256 지문이다.
노드가 NodeHello 로 말하는 호스트 이름은 인증서 CN 과 같아야 한다 — 다르면 감사 스트림 · 영장 구독 모두 `PERMISSION_DENIED`.

```sh
# 맥(중앙 쪽). 결과는 .cache/pki (git 무시). ca.key 는 중앙 밖으로 내보내지 않는다
deploy/pki/pki.sh ca
deploy/pki/pki.sh server localhost 127.0.0.1 host.lima.internal   # 노드가 서버를 부르는 이름 · 주소 전부
deploy/pki/pki.sh node lima-sw                                     # CN = 노드의 hostname

# 노드. ca.pem 과 그 노드의 인증서 · 키만 둔다(키는 0600)
sudo install -d -m 0700 /etc/warrantd/tls
sudo install -m 0644 .cache/pki/ca.pem .cache/pki/nodes/lima-sw.pem /etc/warrantd/tls/
sudo install -m 0600 .cache/pki/nodes/lima-sw.key /etc/warrantd/tls/
sudo deploy/systemd/install.sh -upstream host.lima.internal:9090 \
  -tls-cert /etc/warrantd/tls/lima-sw.pem -tls-key /etc/warrantd/tls/lima-sw.key -tls-ca /etc/warrantd/tls/ca.pem
```

- 서버는 `SPRING_PROFILES_ACTIVE=oidc,mtls` 로 띄운다(`server/README.md`). `mtls` 없이 띄우면 평문이다 — 로컬 개발 전용.
- `-tls-*` 는 셋 다 주거나 셋 다 비운다. 하나라도 빠지면 warrantd 는 평문으로 내려가지 않고 「로컬 전용」으로 돈다(집행은 계속).
- 이미 설치한 노드는 `install.sh` 가 `/etc/default/warrantd` 를 덮어쓰지 않는다 — 그 파일의 `WARRANTD_ARGS` 를 직접 고친다.
- mTLS 전에 `dev:<hostname>` 으로 등록된 노드는 같은 이름의 인증서로 처음 붙을 때 그 행을 넘겨받는다(감사 기록이 한 노드에 남는다).
  인증서끼리는 넘겨받지 않는다 — 같은 이름으로 새 인증서를 만들면 새 노드다.
- 폐기 목록(CRL)은 아직 없다. 노드를 빼려면 CA 를 새로 만들어 남는 노드에 다시 발급하는 수밖에 없다.
- **2026-11-14 실서버로 확인:** 평문 warrantd 는 `error reading server preface: EOF` 로 끊기고, 인증서를 단 warrantd 는
  `resync complete` → VM 로그인 한 건이 `unwarranted_session` 에 들어오며 노드 행이 `dev:lima-sw` → `sha256:9899…` 로 바뀌었다.
  인증서 없이 openssl 로 붙으면 TLS 1.3 `certificate required`(alert 116).

`ansible/` 은 노드가 여러 대가 되는 시점에. 지금은 이르다.

## Grafana (`grafana/`)

화면은 React 목업(동결, 별도 저장소 `session-warrant-web`) 대신 Grafana 가 PostgreSQL 을 직접 읽는다. `server/compose.yaml` 이 띄운다.

```sh
docker compose -f server/compose.yaml up -d --wait    # http://localhost:3000 → 대시보드 「무영장 세션」
```

- `provisioning/datasources` — PostgreSQL 연결(uid `warrant-pg`). 로컬은 warrant 계정이다. **운영은 SELECT 만 가진 계정으로.**
- `provisioning/dashboards` + `dashboards/*.json` — 대시보드는 파일이 원본이다. 화면에서 고쳐도 저장되지 않으니 JSON 을 고치고
  `docker compose -f server/compose.yaml restart grafana`.
- 사유(reason)마다 색이 고정이다(범주 색 1~6번 순서, 검증기 통과). 새 사유를 넣으면 다음 칸 색을 쓴다 — 기존 색을 바꾸지 말 것.
- 「노드」 표의 마지막 등록은 감사 스트림을 연 시각이다. 하트비트가 붙기 전까지 '지금 살아 있음'을 뜻하지 않는다.

### 경보 (`provisioning/alerting/warrant.yaml`)

| 규칙 | 울리는 조건 | 한 경보의 단위 |
|---|---|---|
| 무영장 접속 | 최근 10분 안에 무영장 세션이 있다 | 노드 · 계정 · 사유 · 출발지 · 키 지문 — 알림 한 통으로 누가 들어왔는지 안다 |
| 감사 기록 유실 | 최근 10분 안에 유실 구간이 보고됐다 | 노드 · 원인 |

- 1분마다 평가한다. 10분 창을 벗어나면 '해결됨'이 한 번 더 온다. 같은 경보는 4시간 동안 다시 보내지 않는다.
- 받는 곳은 웹훅 하나다 — `GRAFANA_ALERT_WEBHOOK_URL`. 로컬 기본값은 compose 의 `alert-sink`(받은 요청을 로그로 찍는다):
  `docker compose -f server/compose.yaml logs -f alert-sink`. 운영에서는 이 값을 사내 웹훅(Discord · Teams 등)으로 바꾼다.
- 알림에 대시보드 링크(`panelURL`)가 실린다 — 「최근 무영장 세션」 표가 그 시간대로 열린다.
- 확인(2026-10-29): VM 세션 → DB 16:17:06 → 웹훅 16:17:18 도착(firing). 규칙 쿼리가 깨지면 상태가 `error` 가 된다 —
  `curl -u admin:admin localhost:3000/api/prometheus/grafana/api/v1/rules` 의 `health` 를 본다.

## 규칙

- `/etc/pam.d/sshd` 를 건드리는 작업은 **물리 콘솔 접근이 가능한 상태에서만** 한다.
  ssh 로만 붙어 있는 노드에서 PAM 을 깨면 복구 경로가 없다. 서브 PC 로 개발하는 이유이기도 하다.
- 스파이크 전 구간은 **감사 모드**다. LSM 훅은 `return 0` 만 한다.
  자기보호 6종(§16)을 붙이기 전에 `-EPERM` 을 켜면 자기 발을 쏜다.
- 검증 대상 커널: 6.8(개발) · 7.0(Ubuntu 26.04) · Rocky 9 호환.
