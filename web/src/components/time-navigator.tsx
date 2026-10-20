import { useMemo } from "react"
import { MIN, NOW, events, gaps } from "@/data"
import { HISTORY_START, PAN_STEP, since, type Filters } from "@/lib/filters"
import { usePan } from "@/lib/pan"
import { fmtHM } from "@/lib/format"

const SPAN = NOW - HISTORY_START
const BUCKET = 15 * MIN
const N = SPAN / BUCKET
const pct = (t: number) => ((t - HISTORY_START) / SPAN) * 100

/**
 * 기록 24시간 전체를 한 줄로 놓고, 지금 보는 창을 겹쳐 보인다.
 * 창을 끌거나 · 좌우 스크롤하거나 · 바깥을 눌러 옮긴다. 화살표 키도 된다.
 */
export function TimeNavigator({ filters, onPan, onJump }: { filters: Filters; onPan: (dt: number) => void; onJump: (until: number) => void }) {
  const t0 = since(filters)
  const range = filters.range * MIN

  // 15분 버킷 밀도 — 차단은 판정색, 나머지는 회색. 노드 필터만 따른다
  const rows = useMemo(() => {
    const r = Array.from({ length: N }, () => ({ all: 0, w: 0, d: 0 }))
    events.forEach((e) => {
      if (e.hook === "agg" || e.ts < HISTORY_START || e.ts > NOW) return
      if (filters.node !== "all" && e.node !== filters.node) return
      const b = r[Math.min(N - 1, Math.floor((e.ts - HISTORY_START) / BUCKET))]
      b.all++
      if (e.warrant && e.verdict === "WOULD_DENY") b.w++
      if (e.warrant && e.verdict === "DENY") b.d++
    })
    return r
  }, [filters.node])
  const max = Math.max(1, ...rows.map((r) => r.all))
  const gs = gaps.filter((g) => filters.node === "all" || g.node === filters.node)

  const ref = usePan<HTMLDivElement>({
    msPerPx: (el) => SPAN / (el.clientWidth || 1),
    onPan,
    dragSign: 1,
    // 창 바깥을 누르면 그 지점을 가운데로 뛰고, 이어서 끌 수 있다
    onDown: (e, el) => {
      const r = el.getBoundingClientRect()
      const t = HISTORY_START + ((e.clientX - r.left) / r.width) * SPAN
      if (t < t0 || t > filters.until) onJump(t + range / 2)
    },
  })

  const onKey = (e: React.KeyboardEvent) => {
    const step = e.shiftKey ? range : PAN_STEP
    if (e.key === "ArrowLeft") onPan(-step)
    else if (e.key === "ArrowRight") onPan(step)
    else if (e.key === "Home") onJump(HISTORY_START)
    else if (e.key === "End") onJump(NOW)
    else return
    e.preventDefault()
  }

  const ticks: number[] = []
  for (let t = Math.ceil(HISTORY_START / (3 * 60 * MIN)) * 3 * 60 * MIN; t < NOW; t += 3 * 60 * MIN) ticks.push(t)

  return (
    <div className="min-w-0 flex-1 basis-full sm:basis-0">
      <div
        ref={ref} tabIndex={0} onKeyDown={onKey}
        role="slider" aria-label="보는 시간 창" aria-valuemin={HISTORY_START} aria-valuemax={NOW} aria-valuenow={filters.until}
        aria-valuetext={`${fmtHM(t0)}부터 ${fmtHM(filters.until)}까지`}
        className="group relative h-8 cursor-pointer touch-pan-y select-none overflow-hidden rounded-md border bg-card focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring"
      >
        {/* 밀도 막대 */}
        <div className="absolute inset-x-0 bottom-0 top-1 flex items-end gap-px px-px" aria-hidden>
          {rows.map((r, i) => (
            <div key={i} className="flex h-full flex-1 flex-col justify-end">
              {r.d > 0 && <span className="w-full bg-deny" style={{ height: `${(r.d / max) * 100}%` }} />}
              {r.w > 0 && <span className="w-full bg-would" style={{ height: `${(r.w / max) * 100}%` }} />}
              <span className="w-full bg-muted-foreground/35" style={{ height: `${((r.all - r.w - r.d) / max) * 100}%` }} />
            </div>
          ))}
        </div>
        {gs.map((g) => <span key={`${g.node}${g.seq_from}`} className="hatch absolute inset-y-0 w-1 border-x border-gap/60" style={{ left: `${pct(g.from)}%` }} aria-hidden />)}
        {/* 창 바깥은 흐리게, 창은 테두리로 */}
        <div className="pointer-events-none absolute inset-y-0 left-0 bg-background/45" style={{ width: `${pct(t0)}%` }} aria-hidden />
        <div className="pointer-events-none absolute inset-y-0 right-0 bg-background/45" style={{ width: `${100 - pct(filters.until)}%` }} aria-hidden />
        <div className="pointer-events-none absolute inset-y-0 rounded-[3px] border-2 border-foreground group-data-[dragging]:border-foreground/70" style={{ left: `${pct(t0)}%`, width: `${(range / SPAN) * 100}%` }} aria-hidden />
      </div>
      <div className="relative mt-0.5 h-3.5 font-mono text-[10px] text-muted-foreground" aria-hidden>
        {ticks.filter((t) => pct(t) > 4 && pct(t) < 90).map((t) => <span key={t} className="absolute hidden -translate-x-1/2 sm:inline" style={{ left: `${pct(t)}%` }}>{fmtHM(t)}</span>)}
        <span className="absolute left-0 sm:hidden">{fmtHM(HISTORY_START)}</span>
        <span className="absolute right-0">지금</span>
      </div>
    </div>
  )
}
