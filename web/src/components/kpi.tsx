import { Card, CardContent } from "@/components/ui/card"
import { MIN, type AuditEvent, type Gap } from "@/data"
import { since, type Filters } from "@/lib/filters"
import { fmtHM, fmtN } from "@/lib/format"
import { cn } from "@/lib/utils"

type Tone = "crit" | "would" | "gap" | "ok"

/** 개요 상단 숫자 하나. 아래 칸(viz)에 그 숫자의 시간 모양을 붙인다. */
export function Tile({ label, value, unit, foot, tone, icon, viz }: {
  label: string; value: string | number; unit?: string; foot?: React.ReactNode; tone: Tone
  icon?: React.ReactNode; viz?: React.ReactNode
}) {
  const rule = { crit: "before:bg-deny", would: "before:bg-would", gap: "before:bg-gap", ok: "before:bg-input" }[tone]
  return (
    <Card className={cn("relative gap-0 overflow-hidden py-0 before:absolute before:inset-x-0 before:top-0 before:h-[3px]", rule)}>
      <CardContent className="flex h-full flex-col gap-2 px-4 pb-3.5 pt-4">
        <div className="flex items-center gap-1.5 text-xs font-medium text-ink-2">{icon}{label}</div>
        <div className="flex items-end justify-between gap-3">
          <div className="text-[34px] font-semibold leading-none tracking-tight tabular-nums">
            {value}{unit && <small className="ml-1 text-[13px] font-medium tracking-normal text-muted-foreground">{unit}</small>}
          </div>
          {viz && <div className="mb-0.5 w-[46%] max-w-[150px] shrink-0">{viz}</div>}
        </div>
        {foot && <div className="mt-auto border-t border-dashed pt-2 font-mono text-[11.5px] text-muted-foreground">{foot}</div>}
      </CardContent>
    </Card>
  )
}

/** 차단 판정 스파크라인 — 5분 버킷, WOULD_DENY 아래 · DENY 위. 축 없음, 숫자는 타일이 말한다. */
export function BlockSpark({ filters, events }: { filters: Filters; events: AuditEvent[] }) {
  const bucket = 5 * MIN, n = (filters.range * MIN) / bucket, t0 = since(filters)
  const rows = Array.from({ length: n }, () => ({ w: 0, d: 0 }))
  events.forEach((e) => {
    const i = Math.min(n - 1, Math.floor((e.ts - t0) / bucket))
    if (e.verdict === "WOULD_DENY") rows[i].w++
    else if (e.verdict === "DENY") rows[i].d++
  })
  const max = Math.max(1, ...rows.map((r) => r.w + r.d))
  const W = 150, H = 34, bw = W / n
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="block h-[34px] w-full" role="img" aria-label="5분 단위 차단 판정 추이">
      <line x1="0" x2={W} y1={H - 0.5} y2={H - 0.5} stroke="var(--border)" />
      {rows.map((r, i) => {
        const hw = (r.w / max) * (H - 2), hd = (r.d / max) * (H - 2)
        const x = i * bw + 0.3, w = Math.max(0.6, bw - 0.6)
        return (
          <g key={i} className="[&:hover>.hit]:fill-[var(--muted)]">
            {/* 버킷 전체 높이를 hover 영역으로 — 빈 버킷에도 툴팁이 뜬다 */}
            <rect className="hit" x={i * bw} y={0} width={bw} height={H} fill="transparent" />
            {hw > 0 && <rect x={x} y={H - hw} width={w} height={hw} fill="var(--v-would)" />}
            {hd > 0 && <rect x={x} y={H - hw - hd} width={w} height={hd} fill="var(--v-deny)" />}
            <title>{`${fmtHM(t0 + i * bucket)} · WOULD_DENY ${r.w} · DENY ${r.d}`}</title>
          </g>
        )
      })}
    </svg>
  )
}

/** 유실 구간 띠 — 기간 전체를 한 줄로 놓고 빗금으로 구간을 찍는다. */
export function GapStrip({ filters, gaps }: { filters: Filters; gaps: Gap[] }) {
  const t0 = since(filters), span = filters.until - t0
  const pct = (t: number) => Math.max(0, Math.min(100, ((t - t0) / span) * 100))
  return (
    <div>
      <div className="relative h-4 overflow-hidden rounded-sm bg-muted" role="img" aria-label={`유실 구간 ${gaps.length}개`}>
        {gaps.map((g) => (
          <span key={`${g.node}${g.seq_from}`} title={`${g.node} · ${fmtHM(g.from)} · dropped ${fmtN(g.dropped)}`}
            className="hatch absolute inset-y-0 border-x border-gap" style={{ left: `${pct(g.from)}%`, width: `max(3px, ${pct(g.to) - pct(g.from)}%)` }} />
        ))}
      </div>
      <div className="mt-1 flex justify-between font-mono text-[10px] text-muted-foreground"><span>{fmtHM(t0)}</span><span>{fmtHM(filters.until)}</span></div>
    </div>
  )
}

/** 비율 막대 — 활성 영장 / 전체 */
export function Ratio({ n, of }: { n: number; of: number }) {
  return (
    <div className="flex h-4 gap-0.5" role="img" aria-label={`${of}개 중 ${n}개 활성`}>
      {Array.from({ length: of }, (_, i) => (
        <span key={i} className={cn("flex-1 rounded-sm", i < n ? "bg-ink-2" : "border border-dashed border-input")} />
      ))}
    </div>
  )
}

/** 판정 3색 범례 — 색만으로 뜻을 싣지 않도록 글자를 같이 둔다. */
export function VerdictLegend({ only }: { only?: ("ALLOW" | "WOULD_DENY" | "DENY")[] }) {
  const items = [["ALLOW", "bg-allow"], ["WOULD_DENY", "bg-would"], ["DENY", "bg-deny"]] as const
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[11px] text-muted-foreground">
      {items.filter(([k]) => !only || only.includes(k)).map(([k, c]) => (
        <span key={k} className="flex items-center gap-1.5"><span className={cn("size-2 rounded-[2px]", c)} />{k}</span>
      ))}
    </div>
  )
}
