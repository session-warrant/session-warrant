# deploy/

노드 프로비저닝 · 부트 파라미터 · systemd 유닛.

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

| 유닛 | 하는 일 |
|---|---|
| `warrant-bpf.service` | oneshot. `load-bpf.sh` 가 bpftool 로 `warrant.bpf.o` 를 올려 맵은 `/sys/fs/bpf/warrant`, 프로그램 · 링크는 `/sys/fs/bpf/warrant-progs` 에 pin 한다. **이미 pin 돼 있으면 건너뛴다.** `loader` 가 생기면 없어진다 |
| `warrantd.service` | `Type=notify` — PAM 소켓을 연 뒤 `READY=1` 을 보낸다. `Before=ssh.service sshd.service`. `/run/warrantd` 0700, `Restart=always` |

- **순서가 제품의 조건이다.** sshd 가 PAM 소켓보다 먼저 뜨면 그 사이 세션은 태그 없이 시작된다.
  `Type=simple` 이면 프로세스가 뜨자마자 started 가 되므로 notify 여야 한다.
  Ubuntu 24.04 는 `ssh.socket`(Accept=no)이 `ssh.service` 를 깨운다. 접속은 sshd 가 뜰 때까지 소켓에서 대기하므로
  `Before=ssh.service` 면 충분하다.
- **`Before=ssh.socket` 을 넣지 말 것 — 부팅이 깨진다.** ssh.socket 은 sockets.target → basic.target 보다 먼저이고,
  이 서비스는 기본 의존성으로 basic.target 뒤라 순환이 생긴다. systemd 는 순환을 끊으려고 작업 하나를 **아무거나**
  버린다. 2026-10-24 에 한 번은 sockets.target 을 버려 우연히 통과했고, 다음 부팅에서는 ssh.socket 을 버려
  sshd 가 안 떠서 VM 에 못 들어갔다(Lima provision 스크립트로 복구). **유닛 순서를 바꾸면 재부팅한 뒤
  `journalctl -b | grep -i "ordering cycle"` 이 비어 있는지 반드시 본다** — 서비스가 떴다는 것만으로는 모른다.
- **pin 은 아무도 지우지 않는다.** warrantd 재시작 · 크래시 · `warrant-bpf` 재시작에도 맵(=태그)이 그대로다
  (2026-10-24 VM: 재시작 전후 맵 id 동일, `kill -9` 뒤 자동 재시작). 비우는 건 재부팅뿐이다.
- **부팅 순서 실측(2026-10-24, Lima VM 재부팅, 순환 경고 0줄):**
  `warrant-bpf` Finished 17:12:21.732 → `ssh.socket` Listening 22.612 → `warrantd` Started(READY) 22.703 →
  `ssh.service` Started 23.019. 소켓은 먼저 열려도 sshd 는 PAM 소켓이 준비된 뒤에 뜬다.
  중앙이 꺼져 있어도 warrantd 는 뜨고 업로드만 재시도한다.
- **BPF 를 못 올리면 warrantd 도 안 뜨고, 로그인은 된다.** `Requires=` 는 warrantd 에만 걸고 ssh 에는 걸지 않는다 —
  PAM 은 소켓이 없으면 fail-open 한다(§17). 무영장 세션으로 기록되지 않는 구간이 생기므로 `warrant-bpf` 실패는 경보 대상이다.
- **실제 sshd 로 시험하는 법(2026-10-24 확인).** 원복 타이머를 먼저 건다 — 잘못돼서 못 들어가도 10분 뒤 저절로 빠진다.
  ```sh
  sudo systemd-run --unit=pam-deadman --on-active=10min /usr/bin/make -C $PWD/pam disable
  sudo I_CAN_RECOVER=1 make -C pam enable-sshd TEST_SOCK=/run/warrantd/pam.sock
  # 맥에서. Lima 의 다중화 연결은 새 PAM 세션을 열지 않는다
  ssh -F ~/.lima/sw/ssh.config -o ControlPath=none -o ControlMaster=no lima-sw true
  sudo make -C pam disable && sudo systemctl stop pam-deadman.timer
  ```
  `ExposeAuthInfo` 는 켜지 않아도 된다 — `SSH_AUTH_INFO_0` 은 꺼진 채로 open_session 에 와서 키 지문이 남는다.
- 맵 · 프로그램 이름을 시험 하네스(`bpf/wtest.sh` · `warrantctl` 의 `wtest` · `wmaps`)와 다르게 써서 둘이 섞이지 않는다.

`ansible/` 은 노드가 여러 대가 되는 시점에. 지금은 이르다.

## 규칙

- `/etc/pam.d/sshd` 를 건드리는 작업은 **물리 콘솔 접근이 가능한 상태에서만** 한다.
  ssh 로만 붙어 있는 노드에서 PAM 을 깨면 복구 경로가 없다. 서브 PC 로 개발하는 이유이기도 하다.
- 스파이크 전 구간은 **감사 모드**다. LSM 훅은 `return 0` 만 한다.
  자기보호 6종(§16)을 붙이기 전에 `-EPERM` 을 켜면 자기 발을 쏜다.
- 검증 대상 커널: 6.8(개발) · 7.0(Ubuntu 26.04) · Rocky 9 호환.
