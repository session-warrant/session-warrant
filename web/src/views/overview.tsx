import { Card, CardContent, CardHeader, CardTitle, CardAction } from "@/components/ui/card"
import { EventTable } from "@/components/event-table"
import { TimelineChart } from "@/components/timeline-chart"
import { SeverityChip } from "@/components/pills"
import { BlockSpark, GapStrip, Ratio, Tile, VerdictLegend } from "@/components/kpi"
import { HOOKS, type Hook } from "@/data"
import { baseEvents, blocked, gapsIn, warrantEnd, warrantlessIn, warrantsIn, type Filters } from "@/lib/filters"
import { fmtN, rel } from "@/lib/format"
import { cn } from "@/lib/utils"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { ChevronRight, ShieldAlert } from "lucide-react"

interface Props { filters: Filters; onOpenEvent: (id: string) => void; onOpenSession: (cgroup: number) => void; onPan: (dt: number) => void }

export function Overview({ filters, onOpenEvent, onOpenSession, onPan }: Props) {
  const ev = baseEvents(filters)
  const gaps = gapsIn(filters)
  const wl = warrantlessIn(filters)
  const crit = wl.filter((s) => s.severity === "critical").length
  const deny = ev.filter((e) => e.verdict === "DENY").length
  const would = ev.filter((e) => e.verdict === "WOULD_DENY").length
  const dropped = gaps.reduce((a, g) => a + g.dropped, 0)
  // 창 끝 시각에 살아 있던 영장 / 창과 겹친 영장
  const ws = warrantsIn(filters)
  const active = ws.filter((w) => w.issued <= filters.until && warrantEnd(w) > filters.until)
  const execs = ev.filter((e) => e.hook === "exec" && e.warrant).length

  const byHook: Partial<Record<Hook, { ALLOW: number; WOULD_DENY: number; DENY: number; n: number }>> = {}
  ev.forEach((e) => { if (e.hook === "agg" || !e.warrant) return; const a = (byHook[e.hook] ??= { ALLOW: 0, WOULD_DENY: 0, DENY: 0, n: 0 }); a[e.verdict]++; a.n++ })
  const hookMax = Math.max(1, ...Object.values(byHook).map((a) => a.n))
  const hookOrder: Hook[] = ["exec", "write", "unlink", "rename", "connect", "self"]

  return (
    <div className="flex flex-col gap-5">
      <div className="grid grid-cols-1 gap-3.5 sm:grid-cols-2 xl:grid-cols-4">
        <Tile label="무영장 세션" value={wl.length} unit="세션" tone={wl.length ? "crit" : "ok"}
          icon={wl.length ? <ShieldAlert className="size-3.5 text-deny" /> : undefined}
          viz={wl.length ? <div className="flex flex-col items-end gap-1">{crit > 0 && <span className="rounded bg-deny-wash px-1.5 font-mono text-[11px] font-semibold leading-5 text-deny">critical {crit}</span>}{wl.length - crit > 0 && <span className="rounded bg-warn-wash px-1.5 font-mono text-[11px] font-semibold leading-5 text-warn">warning {wl.length - crit}</span>}</div> : undefined} />
        <Tile label="차단 판정" value={fmtN(deny + would)} unit="건" tone={deny ? "crit" : "would"}
          viz={<BlockSpark filters={filters} events={ev} />}
          foot={`DENY ${fmtN(deny)} · WOULD_DENY ${fmtN(would)}`} />
        <Tile label="감사 유실 구간" value={gaps.length} unit="구간" tone={gaps.length ? "gap" : "ok"}
          viz={<GapStrip filters={filters} gaps={gaps} />}
          foot={`dropped ${fmtN(dropped)}`} />
        <Tile label="활성 영장" value={active.length} unit={`/ ${ws.length}`} tone="ok"
          viz={ws.length ? <Ratio n={active.length} of={ws.length} /> : undefined}
          foot={`exec ${fmtN(execs)}`} />
      </div>

      <Card className="gap-4">
        <CardHeader>
          <CardTitle className="text-sm">판정 추이</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-2">
          <div className="flex flex-wrap items-center gap-3">
            <VerdictLegend />
            <span className="flex items-center gap-1.5 font-mono text-[11px] text-muted-foreground"><span className="hatch size-2.5 rounded-[2px] border border-gap/60" />유실 구간</span>
          </div>
          <TimelineChart filters={filters} events={ev} gaps={gaps} onPan={onPan} />
        </CardContent>
      </Card>

      <div className="grid gap-3.5 lg:grid-cols-[3fr_2fr]">
        <Card className="gap-4">
          <CardHeader>
            <CardTitle className="text-sm">훅별 판정</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            <VerdictLegend />
            <div className="grid grid-cols-[max-content_1fr_max-content] items-center gap-x-3 gap-y-3 text-xs">
              {hookOrder.filter((h) => byHook[h]).map((h) => {
                const a = byHook[h]!
                const [pre, name] = HOOKS[h].split("/")
                return (
                  <div key={h} className="contents">
                    <div className="font-mono text-[11.5px]"><span className="text-muted-foreground">{pre}/</span>{name}</div>
                    <Tooltip>
                      {/* 막대보다 넉넉한 높이를 hover 영역으로 잡는다 */}
                      <TooltipTrigger asChild>
                        <div className="flex h-5 cursor-default items-center" tabIndex={0} aria-label={`${HOOKS[h]} ALLOW ${a.ALLOW} WOULD_DENY ${a.WOULD_DENY} DENY ${a.DENY}`}>
                          <div className="flex h-3 w-full gap-0.5">
                            {(["ALLOW", "WOULD_DENY", "DENY"] as const).map((v) => a[v] > 0 && (
                              <i key={v} className={cn("first:rounded-l-[3px] last:rounded-r-[3px]", { ALLOW: "bg-allow", WOULD_DENY: "bg-would", DENY: "bg-deny" }[v])} style={{ width: `${(a[v] / hookMax) * 100}%` }} />
                            ))}
                          </div>
                        </div>
                      </TooltipTrigger>
                      <TooltipContent side="top" className="px-3 py-2">
                        <div className="mb-1 font-mono text-[11px] opacity-70">{HOOKS[h]}</div>
                        <div className="grid grid-cols-[auto_auto] gap-x-4 font-mono text-[11.5px] tabular-nums">
                          {(["ALLOW", "WOULD_DENY", "DENY"] as const).map((v) => (
                            <div key={v} className="contents"><span className="flex items-center gap-1.5"><span className={cn("size-2 rounded-[2px]", { ALLOW: "bg-allow", WOULD_DENY: "bg-would", DENY: "bg-deny" }[v])} />{v}</span><span className="text-right">{fmtN(a[v])}</span></div>
                          ))}
                        </div>
                      </TooltipContent>
                    </Tooltip>
                    <div className="text-right font-mono tabular-nums text-ink-2">{fmtN(a.n)}{a.DENY + a.WOULD_DENY > 0 && <span className="ml-1.5 text-muted-foreground">차단 {a.DENY + a.WOULD_DENY}</span>}</div>
                  </div>
                )
              })}
            </div>
          </CardContent>
        </Card>
        <Card className="gap-4">
          <CardHeader>
            <CardTitle className="text-sm">무영장 세션</CardTitle>
            <CardAction className="text-xs text-muted-foreground">{wl.length ? `최근 ${rel(Math.max(...wl.map((s) => s.first)))}` : "없음"}</CardAction>
          </CardHeader>
          <CardContent className="flex flex-col gap-2">
            {wl.length ? [...wl].sort((a, b) => b.first - a.first).map((s) => (
              <button key={s.cgroup} onClick={() => onOpenSession(s.cgroup)}
                className={cn("group grid grid-cols-[1fr_auto] items-center gap-x-3 gap-y-1 rounded-md border border-l-[3px] px-3 py-2.5 text-left transition-colors hover:bg-muted focus-visible:outline-2 focus-visible:outline-ring",
                  s.severity === "critical" ? "border-l-deny" : "border-l-warn")}>
                <div className="flex min-w-0 items-center gap-2 text-[13px] font-semibold"><SeverityChip s={s.severity} /><span className="font-mono">{s.node}</span></div>
                <div className="flex items-center gap-1 text-right font-mono text-[11px] tabular-nums text-muted-foreground">{rel(s.first)}<ChevronRight className="size-3.5 transition-transform group-hover:translate-x-0.5" /></div>
                <div className="col-span-2 truncate text-xs text-ink-2">{s.reason}</div>
                <div className="col-span-2 font-mono text-[11px] text-muted-foreground">{s.session} · uid {s.uid}{s.uid === 0 ? " (root)" : ""} · {s.from} · {s.count}건 귀속</div>
              </button>
            )) : <div className="py-6 text-center text-sm text-muted-foreground">없음</div>}
          </CardContent>
        </Card>
      </div>

      <Card className="gap-4 pb-0">
        <CardHeader>
          <CardTitle className="text-sm">최근 차단 판정</CardTitle>
        </CardHeader>
        <EventTable events={ev.filter(blocked).slice(-10)} gaps={[]} onSelect={onOpenEvent} emptyMsg="차단 판정 없음" />
      </Card>
    </div>
  )
}
