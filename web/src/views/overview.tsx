import { Card, CardContent, CardDescription, CardHeader, CardTitle, CardAction } from "@/components/ui/card"
import { EventTable } from "@/components/event-table"
import { TimelineChart } from "@/components/timeline-chart"
import { SeverityChip } from "@/components/pills"
import { HOOKS, NOW, MIN, nodes, warrants, type Hook } from "@/data"
import { baseEvents, blocked, gapsIn, warrantlessIn, type Filters } from "@/lib/filters"
import { fmtN, rel } from "@/lib/format"
import { cn } from "@/lib/utils"

interface Props { filters: Filters; onOpenEvent: (id: string) => void; onOpenSession: (cgroup: number) => void }

function Tile({ label, value, unit, foot, tone }: { label: string; value: string | number; unit?: string; foot: string; tone: "crit" | "would" | "gap" | "ok" }) {
  const border = { crit: "border-l-deny", would: "border-l-would", gap: "border-l-gap", ok: "border-l-input" }[tone]
  return (
    <Card className={cn("gap-1 border-l-[3px] py-3.5", border)}>
      <CardContent className="flex flex-col gap-1 px-4">
        <div className="text-xs text-foreground/70">{label}</div>
        <div className="text-[28px] font-semibold leading-none tracking-tight tabular-nums">{value}{unit && <small className="ml-1 text-[13px] font-medium tracking-normal text-muted-foreground">{unit}</small>}</div>
        <div className="text-xs text-muted-foreground">{foot}</div>
      </CardContent>
    </Card>
  )
}

export function Overview({ filters, onOpenEvent, onOpenSession }: Props) {
  const ev = baseEvents(filters)
  const gaps = gapsIn(filters)
  const wl = warrantlessIn(filters)
  const deny = ev.filter((e) => e.verdict === "DENY").length
  const would = ev.filter((e) => e.verdict === "WOULD_DENY").length
  const dropped = gaps.reduce((a, g) => a + g.dropped, 0)
  const ws = warrants.filter((w) => filters.node === "all" || w.node === filters.node)
  const active = ws.filter((w) => w.expires > NOW || (w.on_expiry === "grace" && w.expires + 120 * MIN > NOW))
  const execs = ev.filter((e) => e.hook === "exec").length

  const byHook: Partial<Record<Hook, { ALLOW: number; WOULD_DENY: number; DENY: number; n: number }>> = {}
  ev.forEach((e) => { if (e.hook === "agg") return; const a = (byHook[e.hook] ??= { ALLOW: 0, WOULD_DENY: 0, DENY: 0, n: 0 }); a[e.verdict]++; a.n++ })
  const hookMax = Math.max(1, ...Object.values(byHook).map((a) => a.n))
  const hookOrder: Hook[] = ["exec", "write", "unlink", "rename", "connect", "self"]

  return (
    <div className="flex flex-col gap-5">
      <div className="grid grid-cols-2 gap-3.5 xl:grid-cols-4">
        <Tile label="무영장 세션" value={wl.length} unit="세션" tone={wl.length ? "crit" : "ok"} foot={`${wl.filter((s) => s.severity === "critical").length}건 critical · 게이트웨이 우회 의심`} />
        <Tile label="차단 판정" value={fmtN(deny + would)} unit="건" tone={deny ? "crit" : "would"} foot={`DENY ${fmtN(deny)} · WOULD_DENY ${fmtN(would)} — 전건 기록`} />
        <Tile label="감사 유실 구간" value={gaps.length} unit="구간" tone={gaps.length ? "gap" : "ok"} foot={`dropped 합계 ${fmtN(dropped)}건 · seq 로 검증`} />
        <Tile label="활성 영장" value={active.length} unit={`/ ${ws.length}`} tone="ok" foot={`귀속된 exec ${fmtN(execs)}건 · 노드 ${filters.node === "all" ? Object.keys(nodes).length : 1}대`} />
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">판정 추이</CardTitle>
          <CardDescription>5분 단위 · 차단은 전건, 허용은 exec·connect 만 (§13)</CardDescription>
          <CardAction className="text-xs text-muted-foreground">빗금 = 감사 유실 구간</CardAction>
        </CardHeader>
        <CardContent><TimelineChart filters={filters} events={ev} gaps={gaps} /></CardContent>
      </Card>

      <div className="grid gap-3.5 lg:grid-cols-[3fr_2fr]">
        <Card>
          <CardHeader><CardTitle className="text-sm">훅별 판정</CardTitle><CardDescription>hook_id 기준 · 집계 행 제외</CardDescription></CardHeader>
          <CardContent>
            <div className="grid grid-cols-[max-content_1fr_max-content] items-center gap-x-2.5 gap-y-1.5 text-xs">
              {hookOrder.filter((h) => byHook[h]).map((h) => {
                const a = byHook[h]!
                return (
                  <div key={h} className="contents">
                    <div className="font-mono text-muted-foreground">{HOOKS[h]}</div>
                    <div className="flex h-2.5 gap-0.5 overflow-hidden rounded-sm bg-muted">
                      {a.ALLOW > 0 && <i className="bg-allow" style={{ width: `${(a.ALLOW / hookMax) * 100}%` }} title={`ALLOW ${a.ALLOW}`} />}
                      {a.WOULD_DENY > 0 && <i className="bg-would" style={{ width: `${(a.WOULD_DENY / hookMax) * 100}%` }} title={`WOULD_DENY ${a.WOULD_DENY}`} />}
                      {a.DENY > 0 && <i className="bg-deny" style={{ width: `${(a.DENY / hookMax) * 100}%` }} title={`DENY ${a.DENY}`} />}
                    </div>
                    <div className="text-right tabular-nums text-foreground/70">{fmtN(a.n)}{a.DENY + a.WOULD_DENY > 0 && <span className="text-muted-foreground"> (차단 {a.DENY + a.WOULD_DENY})</span>}</div>
                  </div>
                )
              })}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">무영장 세션</CardTitle><CardDescription>§07 STEP 2</CardDescription>
            <CardAction className="text-xs text-muted-foreground">{wl.length ? `${wl.length}세션 · 최근 ${rel(Math.max(...wl.map((s) => s.first)))}` : "없음"}</CardAction>
          </CardHeader>
          <CardContent className="flex flex-col gap-2.5">
            {wl.length ? wl.map((s) => (
              <button key={s.cgroup} onClick={() => onOpenSession(s.cgroup)}
                className="grid grid-cols-[1fr_auto] gap-x-3 gap-y-1 rounded-md border px-3 py-2.5 text-left hover:bg-muted focus-visible:outline-2 focus-visible:outline-ring">
                <div className="flex items-center gap-2 text-[13px] font-semibold"><SeverityChip s={s.severity} />{s.node} <span className="font-mono text-xs font-normal text-muted-foreground">{s.session}</span></div>
                <div className="text-right text-xs tabular-nums text-muted-foreground">{rel(s.first)} 시작<br />{s.count}건 귀속</div>
                <div className="col-span-2 text-xs text-foreground/70">uid {s.uid} · {s.from} 에서 · {s.reason}</div>
              </button>
            )) : <div className="py-6 text-center text-sm text-muted-foreground">이 기간에는 무영장 세션이 없습니다</div>}
          </CardContent>
        </Card>
      </div>

      <Card className="pb-0">
        <CardHeader><CardTitle className="text-sm">최근 차단 판정</CardTitle><CardDescription>DENY · WOULD_DENY 최신 10건</CardDescription></CardHeader>
        <EventTable events={ev.filter(blocked).slice(-10)} gaps={[]} onSelect={onOpenEvent} emptyMsg="이 기간에는 차단 판정이 없습니다" />
      </Card>
    </div>
  )
}
