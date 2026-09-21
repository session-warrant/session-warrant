#!/usr/bin/env python3
"""S1 결과를 표로 찍는다.

  python3 report.py out/20260901-000107

매크로는 A 대비 %, 마이크로는 훅 1회당 ns 분포다.
마이크로 절대값을 그대로 % 로 쓰지 말 것 — PROBE 빌드는 계측 비용을 포함한다.
B 를 차감한 뒤 호출수를 곱하는 것이 '검산' 절이고, 결론은 거기서 읽는다.
"""
import json
import math
import os
import re
import statistics as st
import sys
from collections import defaultdict
from glob import glob

# 표시 순서. E 는 D 와 같은 프로그램을 태그 없이 돌린 것이라 D 앞에 놓는다.
TIERS = ["a", "b", "c", "e", "d"]
MICRO_TIERS = ["b", "c", "e", "d"]
TIER_DESC = {
    "a": "훅 없음",
    "b": "return 0 만",
    "c": "+ FMODE_WRITE 앞문",
    "e": "D 와 같음, 영장 없음",
    "d": "+ cgroup·맵2회·시간",
}
PASS_RE = re.compile(r"_p\d+$")


def pct(vals, q):
    if not vals:
        return float("nan")
    i = min(len(vals) - 1, max(0, math.ceil(q * len(vals)) - 1))
    return vals[i]


def load_macro(d):
    """macro_<tier>_<wl>[_p<N>].json 을 티어·워크로드별로 합친다.

    패스를 나눠 교차 실행했으므로 전부 모아야 한 티어의 표본이 된다."""
    out = defaultdict(lambda: defaultdict(list))
    for f in glob(os.path.join(d, "macro_*.json")):
        base = os.path.basename(f)[len("macro_"):-len(".json")]
        base = PASS_RE.sub("", base)
        tier, wl = base.split("_", 1)
        with open(f) as fh:
            out[wl][tier] += json.load(fh)["results"][0]["times"]
    return {wl: {t: sorted(v) for t, v in d2.items()} for wl, d2 in out.items()}


def macro_table(d):
    data = load_macro(d)
    if not data:
        return
    print("── 매크로: 워크로드 벽시계 (A 대비) ─────────────────────────")
    print()
    for wl in sorted(data):
        t = data[wl]
        base = t.get("a")
        n = len(base) if base else 0

        # 훅은 기계를 빠르게 만들 수 없다. A 보다 유의하게 빠른 티어가 있으면
        # 그 워크로드의 Δ 는 전부 인공물이다.
        bogus = []
        if base:
            bm = st.mean(base)
            bse = st.stdev(base) / math.sqrt(len(base)) if len(base) > 1 else 0
            for tier in TIERS[1:]:
                v = t.get(tier)
                if not v:
                    continue
                m = st.mean(v)
                se = math.hypot(bse, st.stdev(v) / math.sqrt(len(v)) if len(v) > 1 else 0)
                if bm - m > 2 * se:
                    bogus.append((tier.upper(), (m / bm - 1) * 100))

        print(f"  {wl}   (n={n})")
        if bogus:
            print("    ⚠ 측정 무효 — 훅이 기준선보다 빠르게 나왔다: "
                  + ", ".join(f"{k} {d:+.1f}%" for k, d in bogus))
            print("      훅은 기계를 빠르게 만들 수 없다. 그 슬롯 동안 기계 상태가")
            print("      변한 것이고(터보 예산·써멀·writeback), 아래 Δ 는 전부 인공물이다.")
            print("      런별 값을 열어 슬롯 안에서 튀는 지점을 찾을 것.")
        print(f"    {'':4} {'설명':<22} {'mean':>9} {'sd':>7} {'p95':>9} "
              f"{'Δmean':>8} {'판정':>12}")
        for tier in TIERS:
            v = t.get(tier)
            if not v:
                continue
            m, sd = st.mean(v), st.stdev(v) if len(v) > 1 else 0.0
            if base and tier != "a":
                bm, bsd = st.mean(base), st.stdev(base) if len(base) > 1 else 0.0
                dm = (m / bm - 1) * 100
                # 두 표본 평균 차이의 표준오차. 이걸 못 넘으면 잰 게 아니다.
                se = math.hypot(sd / math.sqrt(len(v)), bsd / math.sqrt(len(base)))
                sig = "노이즈 이하" if abs(m - bm) < 2 * se else f"±{2*se/bm*100:.1f}% 초과"
                dms = f"{dm:+7.1f}%"
            else:
                dms, sig = "     — ", ""
            print(f"    {tier.upper():<4} {TIER_DESC[tier]:<22} "
                  f"{m:8.3f}s {sd:6.3f}s {pct(v, 0.95):8.3f}s {dms:>8} {sig:>12}")

        # E 와 D 는 같은 프로그램이므로 차이는 영장 유무 하나뿐이다 (§13).
        e, dd = t.get("e"), t.get("d")
        if e and dd:
            em, dm2 = st.mean(e), st.mean(dd)
            ese = math.hypot(st.stdev(e) / math.sqrt(len(e)) if len(e) > 1 else 0,
                             st.stdev(dd) / math.sqrt(len(dd)) if len(dd) > 1 else 0)
            rel = (dm2 / em - 1) * 100
            mark = "노이즈 이하" if abs(dm2 - em) < 2 * ese else f"±{2*ese/em*100:.1f}% 초과"
            print(f"    {'':4} {'└ E→D (영장 유무)':<22} "
                  f"{'':8} {'':6} {'':8}  {rel:+7.1f}% {mark:>12}")
        print()
    print("  '노이즈 이하' 는 오버헤드가 0 이라는 뜻이 아니라 이 표본으로는")
    print("  분해되지 않는다는 뜻이다. 상한으로만 읽고, 필요하면 --passes 를 늘린다.")
    print()


def _probe_files(d):
    out = defaultdict(dict)          # tier -> wl -> path
    for f in sorted(glob(os.path.join(d, "probe_*.json"))):
        base = os.path.basename(f)[len("probe_"):-len(".json")]
        tier, _, wl = base.partition("_")
        out[tier][wl or "(전체)"] = f
    return out


def micro_table(d):
    probes = _probe_files(d)
    if not probes:
        return
    print("── 마이크로: 훅 1회당 소요 (PROBE 빌드) ─────────────────────")
    print()
    print("  PROBE 빌드는 훅마다 bpf_ktime_get_ns() 를 두 번 부른다 — 티어 B 의")
    print("  숫자가 사실상 그 계측 비용이다. 절대값을 매크로 % 로 환산하지 말고")
    print("  티어 간 차이만 읽을 것. 카운터·히스토그램은 타이머 밖에 있다.")
    print()
    wls = sorted({w for m in probes.values() for w in m})
    for wl in wls:
        print(f"  {wl}")
        print(f"    {'':4} {'호출':>10} {'초당':>9} {'쓰기':>13} {'p50':>9} "
              f"{'p90':>9} {'p99':>10} {'p99.9':>11}")
        for tier in MICRO_TIERS:
            f = probes.get(tier, {}).get(wl)
            if not f:
                continue
            with open(f) as fh:
                j = json.load(fh)
            hist = {int(k): v for k, v in j["lat_log2_ns"].items()}
            total = sum(hist.values())
            c = j["counters"]
            opens = c.get("total", total) or total
            secs = j.get("seconds") or 1

            # 쓰기 비중은 dev 히스토그램에서 뽑는다. 판정 경로에서 뽑으면
            # 티어 B 는 그 코드가 없어서 구조적 0 이 측정된 0 처럼 보인다.
            dev = j["dev_major"]
            w = sum(x["write"] for x in dev.values())
            tot = sum(x["read"] + x["write"] for x in dev.values()) or opens

            def q(p):
                if not total:
                    return "—"
                need, acc = total * p, 0
                for b in sorted(hist):
                    acc += hist[b]
                    if acc >= need:
                        return f"{(1 << b) if b else 0}-{(1 << (b + 1)) - 1}"
                return "—"

            print(f"    {tier.upper():<4} {opens:>10,} {opens/secs:>8,.0f} "
                  f"{w:>6,} ({w/tot*100:4.1f}%) {q(.50):>9} {q(.90):>9} "
                  f"{q(.99):>10} {q(.999):>11}")
        # 태그 조회가 실제로 히트했는지. D 에서 0 이면 그 실행은 버린다.
        for tier in ("e", "d"):
            f = probes.get(tier, {}).get(wl)
            if not f:
                continue
            c = json.load(open(f))["counters"]
            print(f"      {tier.upper()} 판정: tag_hit={c.get('tag_hit',0):,} "
                  f"tag_miss={c.get('tag_miss',0):,} "
                  f"read={c.get('read',0):,} expired={c.get('expired',0):,}")
            if tier == "d" and not c.get("tag_hit"):
                print("      경고: tag_hit=0 — 태그가 안 심겼다. 이 D 숫자는 버릴 것")
            if tier == "e" and c.get("tag_hit"):
                print("      경고: E 인데 tag_hit>0 — 태그가 남아 있다. E·D 비교 무효")
        print()


def hook_ns(path):
    """log2 히스토그램에서 훅 1회 평균 ns 를 근사한다.

    버킷 [2^b, 2^(b+1)) 의 대푯값으로 1.5*2^b 를 쓴다. 버킷 폭이 배수라
    산술 중앙값보다 이쪽이 편향이 작다. 절대값이 아니라 티어 간 차이만
    쓰이므로 근사로 충분하다."""
    with open(path) as fh:
        j = json.load(fh)
    hist = {int(k): v for k, v in j["lat_log2_ns"].items()}
    n = sum(hist.values())
    if not n:
        return None, 0
    mean = sum(v * 1.5 * (1 << b) for b, v in hist.items()) / n
    return mean, j["counters"].get("total", n) or n


def crosscheck(d):
    """마이크로로 계산한 예상 Δ 와 매크로 실측 Δ 를 대조한다.

    훅이 커널 안에서 쓴 시간은 마이크로가 직접 잰다. 거기에 호출수를 곱하면
    그 워크로드가 느려질 수 있는 최대치가 나온다 — 훅은 그보다 더 느리게
    만들 수 없다. 매크로가 그 몇 배를 보고하면 그건 훅이 아니라 기계다."""
    probes = _probe_files(d)
    macro = load_macro(d)
    if not probes or not macro:
        return
    print("── 검산: 마이크로 → 매크로 ─────────────────────────────────")
    print()
    print("  예상 Δ = (훅 1회당 판정 비용 × 호출수) / 기준선 시간.")
    print("  훅 1회당 비용은 B(계측 비용) 를 차감한 값이다 — PROBE 빌드가")
    print("  ktime 을 두 번 부르므로 B 의 절대값은 훅이 아니라 계측이다.")
    print("  LSM 부착 비용은 마이크로가 볼 수 없으므로 예상 Δ 는 하한이다.")
    print()
    for wl in sorted(macro):
        base = macro[wl].get("a")
        bref, _ = (hook_ns(probes["b"][wl]) if probes.get("b", {}).get(wl)
                   else (None, 0))
        if not base or bref is None:
            continue
        base_ns = st.mean(base) * 1e9
        # 매크로 노이즈 바닥. 이보다 작은 효과는 이 표본으로 못 잡는다.
        bsd = st.stdev(base) if len(base) > 1 else 0.0
        floor = 2 * (bsd / math.sqrt(len(base))) / st.mean(base) * 100

        print(f"  {wl}   (매크로 노이즈 바닥 ±{floor:.2f}%)")
        print(f"    {'':4} {'1회 net':>9} {'호출':>10} {'총비용':>9} "
              f"{'예상Δ':>8} {'실측Δ':>8} {'배':>6}  판정")
        for tier in ("c", "e", "d"):
            f = probes.get(tier, {}).get(wl)
            v = macro[wl].get(tier)
            if not f or not v:
                continue
            m, opens = hook_ns(f)
            if m is None:
                continue
            net = m - bref
            cost_ms = opens * net / 1e6
            exp = opens * net / base_ns * 100
            got = (st.mean(v) / st.mean(base) - 1) * 100
            ratio = abs(got) / exp if exp > 0.001 else float("inf")
            # 훅이 낼 수 있는 값의 3배를 넘으면 그건 훅이 아니다.
            # (3 은 LSM 부착 비용과 버킷 근사 오차를 넉넉히 덮는 값이다.)
            if abs(got) < floor:
                verdict = "노이즈 이하"
            elif ratio > 3:
                verdict = "⚠ 훅이 낼 수 없는 값"
            else:
                verdict = "설명됨"
            rs = f"{ratio:5.1f}x" if ratio != float("inf") else "    —"
            print(f"    {tier.upper():<4} {net:8.0f}n {opens:>10,} "
                  f"{cost_ms:8.3f}m {exp:+7.2f}% {got:+7.1f}% {rs:>6}  {verdict}")
        if floor > 0:
            worst = max((hook_ns(probes[t][wl])[0] - bref) * hook_ns(probes[t][wl])[1]
                        / base_ns * 100
                        for t in ("c", "e", "d") if probes.get(t, {}).get(wl))
            if worst < floor:
                print(f"    → 예상 Δ 최대 {worst:.2f}% 가 노이즈 바닥 {floor:.2f}% "
                      f"아래다. 이 워크로드는 매크로로 분해될 수 없다.")
                print(f"      런을 늘려도 풀리지 않는다 — 필요 n ≈ "
                      f"{int(len(base) * (floor / max(worst, 1e-9)) ** 2):,}.")
        print()
    print("  '⚠ 훅이 낼 수 없는 값' 은 매크로 Δ 가 커널 안에서 실측한 비용의")
    print("  3배를 넘었다는 뜻이다. 훅은 자기가 쓴 시간보다 더 느리게 만들 수")
    print("  없으므로, 그 Δ 는 기계 상태이지 훅이 아니다. 예상 Δ 쪽을 결론으로")
    print("  적고 매크로는 상한으로만 인용할 것.")
    print()


def dev_table(d):
    probes = _probe_files(d)
    if not probes:
        return
    print("── dev major 분포 (ns 단위 아님, 호출 수) ───────────────────")
    print()
    print("  major 0 은 procfs·sysfs·tmpfs·cgroupfs·pipefs, 259 는 nvme 다.")
    print("  트래픽이 어디에 몰리든 superblock 으로 건너뛰지 않는다 —")
    print("  /proc/sys/kernel/* 쓰기와 /sys/fs/cgroup 조작이 통제 대상이다 (§15).")
    print()
    src = probes.get("d") or probes.get("c") or probes.get("b") or {}
    for wl, f in sorted(src.items()):
        with open(f) as fh:
            dev = json.load(fh)["dev_major"]
        rows = [(int(k), v["read"], v["write"]) for k, v in dev.items()]
        total = sum(r + w for _, r, w in rows)
        if not total:
            continue
        print(f"  {wl}")
        print(f"    {'major':>6} {'read':>11} {'write':>9} {'합':>11} {'비중':>7}")
        for mj, r, w in sorted(rows, key=lambda x: -(x[1] + x[2]))[:6]:
            s = r + w
            print(f"    {mj:>6} {r:>11,} {w:>9,} {s:>11,} {s/total*100:6.1f}%")
        print()


def main():
    d = sys.argv[1] if len(sys.argv) > 1 else "."
    env = os.path.join(d, "env.txt")
    if os.path.exists(env):
        print(open(env).read())
    macro_table(d)
    micro_table(d)
    crosscheck(d)
    dev_table(d)
    print("판정 0: '측정 무효' 가 붙은 워크로드는 판정에 쓰지 않는다.")
    print("판정 1: 오버헤드가 한 자릿수 % 여야 한다. 두 자릿수면 쓰기 통제를")
    print("      inode_* 5종만으로 재설계한다 (CLAUDE.md S1).")
    print("      숫자는 '검산' 절의 예상 Δ 에서 읽는다 — 매크로 Δ 가 아니다.")
    print("      매크로는 상한이다: 전부 '노이즈 이하' 면 통과가 아니라 '이 이상은")
    print("      아니다' 이고, 검산이 그 이유(신호가 노이즈 바닥 아래)를 말해준다.")
    print("판정 2: E→D 차이 = 영장 하나를 조회하는 값. §13 의 '영장 없는 프로세스는")
    print("        조회 한 번으로 빠져나간다'가 참이면 E 는 C 에 가깝고 D 만 더 낸다.")
    print("        E 가 D 만큼 비싸면 그 주장은 거짓이고, 무영장 세션이 많은")
    print("        현실 서버에서 오버헤드 추정이 통째로 틀어진다.")


if __name__ == "__main__":
    main()
