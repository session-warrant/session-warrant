#!/usr/bin/env python3
"""S3 결과를 판정한다.

  python3 report.py out/<타임스탬프>

기획서 §11 T1 의 가정 하나를 참/거짓으로 답한다:
"PAM 스택에서 pam_systemd.so 뒤에 놓으면 session-N.scope 가 이미 있다."
"""
import os
import re
import sys
from collections import Counter, defaultdict

KV = re.compile(r"(\w+)=(\S*)")
# 이미 사용자 세션 안에서 불렸는지. user@N.service 아래(app.slice · vte-spawn 등)
# 이거나 session-N.scope 가 아닌 user.slice 경로면 새 세션이 만들어지지 않은 것이다.
IN_USER_MGR = re.compile(r"/user@\d+\.service/")


def load(path):
    rows = []
    with open(path) as fh:
        for ln in fh:
            if "phase=" in ln:
                rows.append(dict(KV.findall(ln)))
    return rows


def main():
    d = sys.argv[1] if len(sys.argv) > 1 else "."
    env = os.path.join(d, "env.txt")
    if os.path.exists(env):
        print(open(env).read())
    log = os.path.join(d, "pamprobe.log")
    if not os.path.exists(log):
        log = d if os.path.isfile(d) else None
    if not log:
        print("pamprobe.log 가 없다")
        return
    rows = load(log)
    if not rows:
        print("기록이 없다 — 모듈이 안 불렸다. PAM 스택 삽입을 확인할 것")
        return

    by = defaultdict(list)
    for r in rows:
        by[(r.get("service", "?"), r.get("phase", "?"))].append(r)

    print("── 서비스 · 단계별 ──────────────────────────────────────────")
    print()
    print(f"  {'service':<12} {'phase':<15} {'건':>4} {'scope 있음':>11} "
          f"{'proc=scope':>11} {'대기 최대':>10}")
    for (svc, phase), rs in sorted(by.items()):
        ok = sum(1 for r in rs if r.get("present_t0") == "yes")
        match = sum(1 for r in rs if r.get("match") == "yes")
        wmax = max((int(r.get("waited_us", 0) or 0) for r in rs), default=0)
        w = f"{wmax/1000:.1f}ms" if wmax else "0"
        print(f"  {svc:<12} {phase:<15} {len(rs):>4} "
              f"{ok:>4}/{len(rs):<6} {match:>4}/{len(rs):<6} {w:>10}")
    print()

    # ── 판정. sshd 의 open_session 이 유일하게 결론을 내는 자리다.
    sess = [r for r in rows if r.get("phase") == "open_session"]
    ssh = [r for r in sess if r.get("service") == "sshd"]
    target = ssh or sess
    scope_label = "sshd" if ssh else f"{target[0].get('service','?')} (sshd 아님)"

    print("── 판정 ─────────────────────────────────────────────────────")
    print()
    if not target:
        print("  open_session 기록이 없다. 판정 불가.")
        return

    # 호출자가 이미 사용자 세션 안이었던 행은 판정 대상이 아니다 —
    # 실패한 게 아니라 구조적으로 답할 수 없는 행이다. 섞어서 세면
    # 3/11 처럼 보여 통과가 안 보인다.
    excluded = [r for r in target if IN_USER_MGR.search(r.get("proc_cgroup", ""))]
    usable = [r for r in target if r not in excluded]
    if excluded:
        print(f"  판정 제외 {len(excluded)}건 — 호출자가 이미 사용자 세션 안이라")
        print("    새 세션이 만들어지지 않았다 (pam_systemd 가 생성을 건너뛴다).")
        print()
    if not usable:
        print("  ⊘ 판정 불가 — 새 세션이 만들어진 호출이 하나도 없다.")
        print("    → sudo make test-detached  또는  3단계(sshd).")
        return

    target = usable
    n = len(target)
    t0 = sum(1 for r in target if r.get("present_t0") == "yes")
    match = sum(1 for r in target if r.get("match") == "yes")
    sid = sum(1 for r in target if r.get("xdg_session_id", "-") not in ("-", ""))
    waited = [int(r.get("waited_us", 0) or 0) for r in target
              if r.get("present_t0") == "no" and int(r.get("waited_us", 0) or 0)]

    print(f"  대상: {scope_label} · open_session {n}건")
    print()
    print(f"  XDG_SESSION_ID 가 있다        {sid}/{n}")
    print(f"  session-N.scope 가 이미 있다   {t0}/{n}   ← §11 T1 의 가정")
    print(f"  /proc/self/cgroup 과 일치      {match}/{n}")
    print()

    if sid == 0:
        # 원인이 둘인데 대응이 정반대다. proc_cgroup 이 갈라 준다.
        #   (a) 세션이 애초에 안 만들어졌다 — 호출자가 이미 사용자 세션 안이다.
        #       pam_systemd.so 는 그러면 생성을 건너뛴다. 위치는 아무 잘못 없다.
        #   (b) 스택에서 pam_systemd.so 보다 앞에 놓였다.
        # (a) 에서 "위치를 내려라"고 하면 없는 문제를 쫓게 된다.
        inside = [r for r in target if IN_USER_MGR.search(r.get("proc_cgroup", ""))]
        if inside:
            print("  ⊘ 판정 불가 — 새 세션이 만들어지지 않았다.")
            print()
            print(f"    {len(inside)}/{n} 건의 호출자가 이미 사용자 세션 안에 있다:")
            print(f"      {inside[0].get('proc_cgroup','')[:96]}")
            print()
            print("    pam_systemd.so 는 호출한 프로세스가 이미 세션 안이면 세션 생성을")
            print("    건너뛴다. 그래서 XDG_SESSION_ID 가 안 붙고 잴 대상 자체가 없다.")
            print("    삽입 위치 문제가 아니다 — 위치를 내려도 결과는 같다.")
            print()
            print("    → 진짜 새 세션이 필요하다. 둘 중 하나:")
            print("       sudo make test-detached      system.slice 에서 pamtester")
            print("       sudo make enable-sshd + ssh  확실한 쪽. 3단계")
        else:
            print("  ✗ XDG_SESSION_ID 가 비었다. 새 세션은 만들어졌는데 모듈이")
            print("    그 값을 못 봤다 — pam_systemd.so 보다 앞에 놓였을 가능성이 크다.")
            print("    → PAM 스택에서 삽입 위치를 내리고 다시 잰다.")
    elif sid < n:
        print(f"  ⚠ {n-sid}/{n} 건에만 XDG_SESSION_ID 가 없다. 서비스가 섞여 있다 —")
        print("    아래 '서비스 · 단계별' 표에서 어느 서비스인지 보고 그것만 다시 잰다.")
    elif t0 == n:
        print("  ✓ S3 통과. session 단계에서 scope 가 이미 확정돼 있다.")
        print("    pam_warrant.so 는 XDG_SESSION_ID → 경로 → stat 만으로 cgroup id 를")
        print("    얻을 수 있다. warrantd 의 cgroup 트리 순회는 필요 없다.")
        if match < n:
            print()
            print(f"  ⚠ 다만 {n-match}건에서 /proc/self/cgroup 과 scope 가 다르다.")
            print("    sshd 프로세스 자신은 아직 이관 전일 수 있다 — 제품은")
            print("    /proc/self/cgroup 이 아니라 XDG_SESSION_ID 경로를 써야 한다.")
    elif t0 == 0 and waited:
        lo, hi = min(waited) / 1000, max(waited) / 1000
        print(f"  ✗ S3 실패. scope 가 t0 에 없고 {lo:.1f}~{hi:.1f}ms 뒤에 나타난다.")
        print("    → 이게 태깅 공백이다. 이 구간에 태어난 프로세스는 태그가 없다.")
        print("    → warrantd 가 cgroup 트리를 순회하거나, logind 의 D-Bus")
        print("      SessionNew 를 구독해야 한다. pam/ 와 agent/ 설계가 바뀐다.")
    elif t0 == 0:
        print("  ✗ S3 실패. scope 가 상한(wait_ms) 안에 나타나지 않았다.")
        print("    → 삽입 위치를 확인하고, 맞다면 상한을 올려 다시 잰다.")
    else:
        print(f"  ⚠ 불안정. {n}건 중 {t0}건만 t0 에 있었다.")
        print("    간헐적이면 그게 가장 나쁜 결과다 — 공백이 재현되지 않으면")
        print("    제품에서 언제 태그가 빠졌는지 사후에 알 수 없다.")
        if waited:
            print(f"    나머지는 {min(waited)/1000:.1f}~{max(waited)/1000:.1f}ms 뒤에 나타났다.")

    # XDG_SESSION_ID 는 재사용되고 cgroup id 는 안 된다 — 키가 cgroup id 인 이유.
    by_sid = defaultdict(set)
    for r in target:
        sid_v = r.get("xdg_session_id", "-")
        if sid_v not in ("-", ""):
            by_sid[sid_v].add(r.get("scope_cgid"))
    reused = {k: v for k, v in by_sid.items() if len(v) > 1}
    if reused:
        print()
        print("  ★ XDG_SESSION_ID 가 재사용됐다 — cgroup id 는 매번 다르다:")
        for k, v in sorted(reused.items()):
            print(f"      session-{k}.scope  →  cgid {', '.join(sorted(v))}")
        print("    같은 세션 번호가 서로 다른 cgroup 을 가리켰다. 영장을 세션")
        print("    번호에 걸면 다음 세션이 남의 영장을 물려받는다.")
        print("    → cgroup id 를 키로 쓰는 §11 T1 설계가 옳다는 직접 증거다.")

    # close_session — §11 T4 의 정리 시점
    cl = [r for r in rows if r.get("phase") == "close_session"]
    if cl:
        alive = sum(1 for r in cl if r.get("present_t0") == "yes")
        print()
        print(f"  (§11 T4) close_session {len(cl)}건 중 scope 가 아직 살아 있음: {alive}")
        print("    살아 있으면 cgroup_warrant 엔트리 정리를 여기에 걸 수 있다.")

    acct = [r for r in rows if r.get("phase") == "acct_mgmt"]
    if acct:
        a = sum(1 for r in acct if r.get("present_t0") == "yes")
        print()
        print(f"  (§11 T1) acct_mgmt {len(acct)}건 중 scope 있음: {a}")
        print("    account 단계는 영장 유무만 본다. 0 이 정상이다 —")
        print("    0 이 아니면 바인딩을 앞당길 여지가 있다는 뜻이다.")

    svcs = Counter(r.get("service") for r in rows)
    if not ssh:
        print()
        print(f"  주의: sshd 기록이 없다. 지금까지 본 서비스 = {dict(svcs)}")
        print("    su 와 pamtester 는 기존 세션 안에서 불리면 새 세션을 만들지")
        print("    않으므로 §11 T1 을 잴 수 없다 — 모듈이 안 죽는다는 것만 확인된다.")
        print("    결론은 test-detached 또는 3단계(sshd)에서 나온다.")


if __name__ == "__main__":
    main()
