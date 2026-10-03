# pam/

C · `pam_warrant.so`. sshd 주소 공간에 dlopen 되므로 **Go 런타임을 넣을 수 없다.**
**200줄 이내로 유지한다** — 여기가 커지면 sshd 가 죽는다.

## 하는 일

1. `pam_sm_open_session` 에서 `XDG_SESSION_ID` 를 읽는다.
2. `session-N.scope` cgroup 경로를 stat 해서 cgroup id 를 얻는다.
3. `pam_getenv("SSH_AUTH_INFO_0")` 원문을 읽는다. **지문 계산은 하지 않는다** — warrantd 가 한다 (`proto/README.md` 미해결 1).
4. warrantd 에 유닉스 소켓으로 `(login_account, cgroup_id, host, auth_info 원문)` 을 넘긴다.
5. 응답을 기다리지 않는다 — 태그를 맵에 박는 건 warrantd 의 몫이다.

## 빌드 · 검증

`bench/pamtiming` 과 같은 사다리다. 단계를 건너뛰지 않는다.

```sh
make check                              # 도구 · 모듈 디렉터리 · PrivateTmp
make                                    # 빌드 + 심볼 검사 (pam_sm_* 6개, wr_* 노출 0)
sudo make install                       # 모듈 디렉터리로 · 테스트 서비스 생성
sudo make listen                        # ← 다른 터미널. warrantd 대신 받아 찍는다
sudo make test                          # 1단계   세션 안
sudo make test-detached                 # 1.5단계 세션 밖 — 실제 세션 번호 · cgroup id
sudo I_CAN_RECOVER=1 make enable-sshd   # 3단계   복구 경로 확보 후에만
sudo make disable                       # 넣은 줄 · 테스트 서비스 제거
make status                             # 설치본이 최신인가 · sshd 에 들어가 있나
```

- 3단계의 새 접속은 **다중화 없이** 한다 (`ssh -o ControlPath=none …`). ControlMaster 로
  다중화된 창은 PAM 세션을 새로 열지 않아 모듈이 안 불린다.
- 제품 설치는 `socket=` 없이: `sudo I_CAN_RECOVER=1 make enable-sshd PAM_ARGS=`.
- `.so` 는 빌드한 기계의 아키텍처 전용이다. 서브 PC 에서는 거기서 다시 빌드한다.
- 검증 기록: `docs/experiments.md` S3 「후속」 (2026-09-26, Lima VM).

## 규칙

- **fail-open.** warrantd 에 못 붙으면 **로그인을 허용**하고 무영장 세션으로 기록·경보한다.
  여기서 fail-close 를 택하면 장애 때 아무도 못 들어간다 (§17).
- PAM 스택에서 `pam_systemd.so` **뒤에** 온다. 그 전에는 `session-N.scope` 가 아직 없다.
- `/etc/pam.d/sshd` 를 건드리는 작업은 **VM 콘솔 접근 경로를 확보한 상태에서만** 한다.
- 블로킹 금지. 소켓에는 짧은 타임아웃을 걸고, 넘으면 그냥 통과시킨다.
- malloc 실패·긴 문자열에서 sshd 를 죽이지 않는다. 모든 실패 경로가 `PAM_SUCCESS` 로 끝나야 한다.
