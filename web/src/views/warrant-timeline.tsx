import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { EventTable } from "@/components/event-table"
import { ModeChip } from "@/components/pills"
import { Deed, GRACE, STATUS_KO, statusOf } from "@/components/warrant-card"
import { NOW, MIN, events, gaps, warrantById, type Warrant } from "@/data"
import { blocked, warrantsIn, type Filters } from "@/lib/filters"
import { fmtHM, fmtN, rel, subjName } from "@/lib/format"
import { cn } from "@/lib/utils"

interface Props { filters: Filters; warrant: string | null; setWarrant: (id: string) => void; onOpenEvent: (id: string) => void }
/** 유효기간 띠 — 발급 · 만료 · 유예 · 지금을 한 축에. 30분 눈금. */
function ValidityBand({ w }: { w: Warrant }) {
  const graceEnd = w.on_expiry === "grace" ? w.expires + GRACE : null
  const t0 = w.lineage[0].t, t1 = Math.max(graceEnd ?? w.expires, NOW) + 5 * MIN
  const px = (t: number) => ((t - t0) / (t1 - t0)) * 100
  const ticks: number[] = []
  for (let t = Math.ceil(t0 / (30 * MIN)) * 30 * MIN; t < t1; t += 30 * MIN) ticks.push(t)
  const exts = w.lineage.filter((l) => l.kind.startsWith("연장"))
  return (
    <div>
      <div className="relative h-7 rounded-[4px] bg-muted" role="img" aria-label={`유효 ${fmtHM(w.issued)}–${fmtHM(w.expires)}`}>
        <div className="absolute inset-y-0 rounded-l-[4px] border-r-2 border-foreground bg-accent" style={{ left: `${px(w.issued)}%`, width: `${px(w.expires) - px(w.issued)}%` }}>
          <span className="absolute left-0 top-1/2 -translate-y-1/2 px-2 font-mono text-[11px] text-ink-2">유효</span>
        </div>
        {graceEnd && <div className="hatch-warn absolute inset-y-0 rounded-r-[4px]" style={{ left: `${px(w.expires)}%`, width: `${px(graceEnd) - px(w.expires)}%` }}><span className="absolute left-0 top-1/2 -translate-y-1/2 px-2 font-mono text-[11px] text-warn">유예</span></div>}
        {exts.map((l) => <span key={l.t} title={`${l.kind} · ${l.who}`} className="absolute -top-1 size-2 -translate-x-1/2 rotate-45 bg-foreground" style={{ left: `${px(l.t)}%` }} />)}
        <div className="absolute -inset-y-1.5 w-0.5 -translate-x-1/2 rounded bg-deny" style={{ left: `${px(NOW)}%` }}>
          <span className="absolute -top-5 left-1/2 -translate-x-1/2 whitespace-nowrap rounded bg-deny px-1.5 font-mono text-[10.5px] font-semibold leading-4 text-white dark:text-black">지금</span>
        </div>
      </div>
      <div className="relative mt-1.5 h-4 font-mono text-[10.5px] text-muted-foreground">
        {ticks.filter((t) => px(t) > 3 && px(t) < 96).map((t) => <span key={t} className="absolute -translate-x-1/2 whitespace-nowrap" style={{ left: `${px(t)}%` }}>{fmtHM(t)}</span>)}
      </div>
      <div className="mt-1 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-muted-foreground">
        <span className="flex items-center gap-1.5"><span className="size-2 rotate-45 bg-foreground" />연장 승인</span>
        <span className="flex items-center gap-1.5"><span className="h-2.5 w-0.5 bg-deny" />기준 시각</span>
        {graceEnd && <span className="flex items-center gap-1.5"><span className="hatch-warn size-2.5 rounded-[2px]" />유예</span>}
      </div>
    </div>
  )
}

export function WarrantTimeline({ filters, warrant, setWarrant, onOpenEvent }: Props) {
  // 보고 있는 시간 창과 겹치는 영장만 — 과거로 스크롤하면 그때의 영장이 나온다
  const ws = warrantsIn(filters)
  const w = (warrant && ws.find((x) => x.id === warrant)) ? warrantById[warrant] : ws[0]

  return (
    <div className="flex flex-col gap-4">
      <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-4" role="tablist" aria-label="영장">
        {ws.map((x) => {
          const st = statusOf(x), on = w?.id === x.id
          const pct = Math.max(0, Math.min(100, ((NOW - x.issued) / (x.expires - x.issued)) * 100))
          return (
            <button key={x.id} role="tab" onClick={() => setWarrant(x.id)} aria-selected={on}
              className={cn("flex flex-col gap-1.5 rounded-md border bg-card px-3 py-2.5 text-left transition-colors hover:bg-muted focus-visible:outline-2 focus-visible:outline-ring", on && "border-foreground ring-1 ring-foreground")}>
              <span className="flex items-center justify-between gap-1.5"><span className="font-mono text-[13px] font-semibold">{x.id}</span><ModeChip mode={x.mode} /></span>
              <span className="truncate text-xs text-ink-2">{subjName(x.subject)} · <span className="font-mono">{x.node}</span></span>
              <span className="flex items-center gap-2">
                <span className="h-1 flex-1 overflow-hidden rounded-full bg-muted"><span className={cn("block h-full", st === "active" ? "bg-foreground" : st === "grace" ? "bg-warn" : "bg-muted-foreground/50")} style={{ width: `${pct}%` }} /></span>
                <span className={cn("font-mono text-[10.5px]", st === "grace" ? "text-warn" : "text-muted-foreground")}>{st === "active" ? rel(x.expires) : STATUS_KO[st]}</span>
              </span>
            </button>
          )
        })}
      </div>
      {!w ? <Card><CardContent className="py-8 text-center text-sm text-muted-foreground">이 기간 · 노드에는 영장이 없습니다</CardContent></Card> : (() => {
        const ev = events.filter((e) => e.warrant === w.id)
        const gs = gaps.filter((g) => g.node === w.node && g.from >= w.issued)
        const lineage = [...w.lineage.map((l) => ({ ...l, now: false })), ...(w.expires > NOW ? [{ t: NOW, kind: "지금", who: `만료까지 ${rel(w.expires).replace(" 후", "")}`, note: "", now: true }] : [])]
        return (<>
          <div className="grid items-start gap-4 xl:grid-cols-[minmax(0,1.1fr)_minmax(0,1fr)]">
            <div className="flex flex-col gap-4">
              <Deed w={w} />
              <Card className="gap-6">
                <CardHeader><CardTitle className="text-sm">유효기간</CardTitle></CardHeader>
                <CardContent><ValidityBand w={w} /></CardContent>
              </Card>
            </div>
            <Card className="gap-4">
              <CardHeader><CardTitle className="text-sm">계보</CardTitle></CardHeader>
              <CardContent>
                <ol className="flex flex-col">
                  {lineage.map((l, i, arr) => (
                    <li key={i} className="relative grid grid-cols-[44px_14px_1fr] gap-x-3 pb-4 last:pb-0">
                      {i < arr.length - 1 && <span className="absolute left-[62px] top-4 -bottom-0.5 w-px bg-input" aria-hidden />}
                      <span className="pt-px font-mono text-xs text-muted-foreground">{fmtHM(l.t)}</span>
                      <span className={cn("z-[1] mt-1 size-3 rounded-full border-2 border-foreground bg-card", /만료/.test(l.kind) && "border-muted-foreground bg-muted-foreground", l.now && "border-deny bg-deny ring-4 ring-deny/15")} />
                      <span className="text-[13px]">
                        <span className={cn("font-semibold", l.now && "text-deny")}>{l.kind}</span> <span className="text-xs text-muted-foreground">· {l.who}</span>
                        {l.note && <span className="mt-1 block rounded-[4px] border-l-2 border-input bg-muted/60 px-2.5 py-1.5 text-xs text-ink-2">{l.note}</span>}
                      </span>
                    </li>
                  ))}
                </ol>
              </CardContent>
            </Card>
          </div>
          <Card className="gap-4 pb-0">
            <CardHeader><CardTitle className="text-sm">이 영장의 이벤트</CardTitle><CardDescription>{fmtN(ev.length)}건 · 차단 {fmtN(ev.filter(blocked).length)} · 유실 구간 {gs.length}</CardDescription></CardHeader>
            <EventTable events={ev} gaps={gs} onSelect={onOpenEvent} />
          </Card>
        </>)
      })()}
    </div>
  )
}
