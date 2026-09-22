# pam/

C · `pam_warrant.so`. sshd 주소 공간에 dlopen 되므로 **Go 런타임을 넣을 수 없다.**
**200줄 이내로 유지한다** — 여기가 커지면 sshd 가 죽는다.

## 하는 일

1. `pam_sm_open_session` 에서 `XDG_SESSION_ID` 를 읽는다.
2. `session-N.scope` cgroup 경로를 stat 해서 cgroup id 를 얻는다.
3. `pam_getenv("SSH_AUTH_INFO_0")` 원문을 읽는다. **지문 계산은 하지 않는다** — warrantd 가 한다 (`proto/README.md` 미해결 1).
4. warrantd 에 유닉스 소켓으로 `(login_account, cgroup_id, host, auth_info 원문)` 을 넘긴다.
5. 응답을 기다리지 않는다 — 태그를 맵에 박는 건 warrantd 의 몫이다.

## 규칙

- **fail-open.** warrantd 에 못 붙으면 **로그인을 허용**하고 무영장 세션으로 기록·경보한다.
  여기서 fail-close 를 택하면 장애 때 아무도 못 들어간다 (§17).
- PAM 스택에서 `pam_systemd.so` **뒤에** 온다. 그 전에는 `session-N.scope` 가 아직 없다.
- `/etc/pam.d/sshd` 를 건드리는 작업은 **VM 콘솔 접근 경로를 확보한 상태에서만** 한다.
- 블로킹 금지. 소켓에는 짧은 타임아웃을 걸고, 넘으면 그냥 통과시킨다.
- malloc 실패·긴 문자열에서 sshd 를 죽이지 않는다. 모든 실패 경로가 `PAM_SUCCESS` 로 끝나야 한다.
