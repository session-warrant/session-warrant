#!/usr/bin/env python3
"""S4 결과를 카탈로그로 찍는다.

  python3 report.py out/<타임스탬프>

산출물은 숫자가 아니라 목록이다 — "어느 시점에 inode 가 바뀌는가"(§09 S4).
그리고 그보다 중요한 것: 바뀌었는데 fanotify 가 안 알려준 케이스가 있는가.
"""
import csv
import os
import sys


def main():
    d = sys.argv[1] if len(sys.argv) > 1 else "."
    env = os.path.join(d, "env.txt")
    if os.path.exists(env):
        print(open(env).read())
    path = os.path.join(d, "cases.csv")
    if not os.path.exists(path):
        print("cases.csv 가 없다")
        return
    rows = list(csv.DictReader(open(path)))
    if not rows:
        print("케이스가 없다")
        return

    cases = [r for r in rows if r["kind"] in ("allow", "deny")]
    claims = [r for r in rows if r["kind"] == "claim"]

    for kind, title, why in (
        ("allow", "허용 목록 — 파일 inode 로 걸린다",
         "바뀌면 그 영장의 실행·쓰기 허용이 조용히 무효가 된다."),
        ("deny", "금지 목록 — 디렉터리 inode 로 걸린다 (§15)",
         "바뀌면 금지가 조용히 풀린다. 허용이 풀리는 것보다 훨씬 나쁘다."),
    ):
        sel = [r for r in cases if r["kind"] == kind]
        if not sel:
            continue
        print(f"── {title} ──")
        print(f"   {why}")
        print()
        print(f"   {'조작':<30} {'inode':>6} {'dev':>5} {'fanotify':>9}  판정")
        for r in sel:
            ch = r["changed"]
            devch = "바뀜" if r["dev_before"] != r["dev_after"] else "-"
            fan = int(r["fanotify"])
            if ch == "yes" and fan == 0:
                v = "✗ 재컴파일 필요한데 못 잡는다"
            elif ch == "yes":
                v = "재컴파일 — fanotify 가 잡는다"
            elif fan > 0:
                v = "그대로 (이벤트만 옴)"
            else:
                v = "그대로"
            print(f"   {r['case']:<30} {ch:>6} {devch:>5} {fan:>7}건  {v}")
        print()

    if claims:
        print("── 문서의 주장 검증 ──")
        print()
        for r in claims:
            same = r["changed"] == "no"
            if r["case"] == "bind-mount":
                print(f"   bind mount        (dev,ino) {'동일' if same else '다름'} — "
                      + ("우회 안 됨 ✓ §15 주장 참" if same else "✗ §15 주장 반증"))
            elif r["case"] == "binary-copy":
                print(f"   바이너리 복사      (dev,ino) {'동일' if same else '다름'} — "
                      + ("✗ 복사 우회가 뚫린다" if same else "복사 우회 자동 차단 ✓"))
            elif r["case"] == "hardlink":
                print(f"   하드링크          (dev,ino) {'동일' if same else '다름'} — "
                      + ("⚠ 허용이 딸려간다" if same else "별개 inode"))
        print()

    # 이 스파이크의 실패 조건은 하나뿐이다: 바뀌었는데 fanotify 가 못 잡은 케이스.
    missed = [r for r in cases if r["changed"] == "yes" and int(r["fanotify"]) == 0]
    changed = [r for r in cases if r["changed"] == "yes"]
    deny_changed = [r for r in cases if r["kind"] == "deny" and r["changed"] == "yes"]

    print("── 판정 ──")
    print()
    print(f"   inode 가 바뀌는 조작   {len(changed)}/{len(cases)}")
    print(f"   그중 fanotify 미검출   {len(missed)}")
    print()
    if not changed:
        print("   ⊘ 판정 불가 — 아무 조작도 inode 를 바꾸지 않았다. 케이스를 의심할 것.")
    elif not missed:
        print("   ✓ S4 통과. inode 가 바뀌는 지점이 목록화됐고, 전부 fanotify 로 잡힌다.")
        print("     warrantd 가 이벤트를 받아 (dev, ino) 를 다시 컴파일하면 된다.")
        print("     fanotify 범위 확대는 필요 없다.")
    else:
        print("   ✗ S4 실패. 아래 조작은 inode 를 바꾸는데 fanotify 가 못 잡았다:")
        for r in missed:
            print(f"       {r['case']}  ({r['target']})")
        print("     → 정책이 조용히 무효가 되는 구간이다. fanotify 마스크·범위를")
        print("       넓히거나, 주기적 재stat 로 메워야 한다 (CLAUDE.md S4).")

    if deny_changed:
        print()
        print("   ⚠ 금지 목록 쪽에서 디렉터리 inode 가 바뀐 조작이 있다:")
        for r in deny_changed:
            print(f"       {r['case']}")
        print("     금지는 허용과 달리 '조용히 풀리는' 방향이라 더 위험하다.")
        print("     디렉터리 교체를 막는 규칙이 따로 필요한지 §15 로 돌아가 볼 것.")


if __name__ == "__main__":
    main()
