#!/usr/bin/env python3
"""k6 요약을 서버 부하 보고서로 바꾼다.

  python3 report.py out/<타임스탬프> --rows-before N --rows-after M --nodes 8 --duration 60

숫자 하나만 보면 안 된다. 처리량은 「DB 에 실제로 들어온 건수 ÷ 시간」이고,
k6 가 보낸 건수는 상한일 뿐이다 — 멱등에 걸려 전건 중복으로 버려지면
k6 쪽은 빠르게 끝나고 DB 는 안 늘어난다. 그걸 판정으로 적는다.
"""
import argparse
import json
import os
import sys


def metric(data, name):
    return (data.get("metrics") or {}).get(name, {}).get("values", {})


def fmt_ms(v):
    return "-" if v is None else f"{v:,.1f}ms"


def latency_line(label, m, n=None):
    """k6 기본 요약은 avg · min · med · max · p(90) · p(95) 만 준다. p99 는 없다."""
    if not m:
        return f"   {label:<22} -"
    line = (f"   {label:<22} 평균 {fmt_ms(m.get('avg')):>9}   "
            f"중위 {fmt_ms(m.get('med')):>9}   p95 {fmt_ms(m.get('p(95)')):>9}   "
            f"최대 {fmt_ms(m.get('max')):>9}")
    return line if n is None else f"{line}   n={n:,}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dir")
    ap.add_argument("--rows-before", type=int, default=0)
    ap.add_argument("--rows-after", type=int, default=0)
    ap.add_argument("--nodes", type=int, default=1)
    ap.add_argument("--duration", type=float, default=0)
    ap.add_argument("--mode", default="ingest")
    a = ap.parse_args()

    env = os.path.join(a.dir, "env.txt")
    if os.path.exists(env):
        print(open(env).read())

    verdict = 0

    if a.mode != "read":
        path = os.path.join(a.dir, "ingest-summary.json")
        if not os.path.exists(path):
            print("── 쓰기 ──\n   ingest-summary.json 이 없다 — ingest.log 를 볼 것\n")
            verdict = 1
        else:
            d = json.load(open(path))
            sent = int(metric(d, "ingest_events_sent").get("count", 0))
            acked = int(metric(d, "ingest_events_acked").get("count", 0))
            batches = int(metric(d, "ingest_batches_sent").get("count", 0))
            landed = a.rows_after - a.rows_before
            secs = a.duration or 1

            print("── 쓰기 — 감사 수집 (gRPC 스트림) ──")
            print(f"   노드 {a.nodes}대 · 배치 {batches:,}개 · {secs:.0f}초")
            print()
            print(f"   {'보낸 이벤트':<22} {sent:>12,}    {sent / secs:>10,.0f}/s   ← 상한")
            print(f"   {'ack 된 이벤트':<22} {acked:>12,}    {acked / secs:>10,.0f}/s")
            print(f"   {'DB 에 들어온 행':<22} {landed:>12,}    {landed / secs:>10,.0f}/s   ← 이게 처리량이다")
            print(f"   {'노드 1대당':<22} {'':>12}    {landed / secs / max(a.nodes, 1):>10,.0f}/s")
            print()
            print(latency_line("ack 지연", metric(d, "ingest_ack_latency"),
                               int(metric(d, "grpc_streams_msgs_received").get("count", 0))))
            print()

            # 멱등에 걸려 버려지면 k6 는 빨랐다고 하고 DB 는 안 늘어난다.
            if sent and landed <= 0:
                print("   ✗ 보냈는데 DB 가 안 늘었다. epoch 를 새로 안 뽑았거나(멱등으로 전건 중복),")
                print("     매퍼가 거부했거나, 다른 노드 이름으로 들어갔다. ingest.log 와 서버 로그를 볼 것.")
                verdict = 1
            elif sent and landed < sent * 0.99:
                print(f"   ✗ 보낸 것의 {landed / sent:.1%} 만 들어왔다 — {sent - landed:,}건이 비었다.")
                print("     ack 를 받고도 안 들어온 것이면 적재 쪽 결함이다.")
                verdict = 1
            elif acked and acked < sent:
                print(f"   ⚠ ack 를 {sent - acked:,}건 못 받고 끝났다(DB 에는 들어왔다). 대기 시간이 짧았을 수 있다.")

            if verdict == 0 and sent:
                print("   ✓ 보낸 만큼 들어왔다. 위 처리량은 실제 적재 기준이다.")
            print()

    if a.mode != "ingest":
        path = os.path.join(a.dir, "read-summary.json")
        if not os.path.exists(path):
            print("── 읽기 ──\n   read-summary.json 이 없다 — read.log 를 볼 것\n")
            verdict = 1
        else:
            d = json.load(open(path))
            print("── 읽기 — 대시보드 API ──")
            fails = int(metric(d, "checks").get("fails", 0))
            passes = int(metric(d, "checks").get("passes", 0))
            reqs = int(metric(d, "http_reqs").get("count", 0))
            print(f"   요청 {reqs:,}건 · 200 아님 {fails:,}건")
            print()
            for label, name in (
                ("처음 화면 events", "read_events"),
                ("이어 받기 after=", "read_events_after"),
                ("구간 집계 summary", "read_summary"),
                ("노드 목록", "read_nodes"),
                ("무영장 세션", "read_unwarranted"),
            ):
                print(latency_line(label, metric(d, name)))
            print()
            if fails:
                print(f"   ✗ 200 아닌 응답이 {fails:,}건 있다. 인증(401)인지 서버 오류(5xx)인지 read.log 에서 가른다.")
                verdict = 1
            elif passes:
                print("   ✓ 전건 200.")
            print()

    print("── 읽을 때 ──")
    print("   · 노드 수를 올려도 「DB 에 들어온 행/s」가 안 늘면 적재가 직렬화된 것이다 —")
    print("     서버는 받은 순번을 advisory lock 으로 직렬화한다(V4). 설계대로지만 상한이 생긴다.")
    print("   · audit_event 는 지금 DEFAULT 파티션 하나뿐이다. 행이 쌓이면 읽기가 같이 느려진다.")
    print("   · 이 숫자는 맥 한 대에서 서버 · DB · k6 가 같이 돌 때의 값이다. 서로 CPU 를 다툰다.")
    print("     실행끼리 섞어 비교하지 말 것 — 같은 실행 안의 노드 수 비교로만 읽는다.")
    return verdict


if __name__ == "__main__":
    sys.exit(main())
