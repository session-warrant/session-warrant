import { Bar, BarChart, CartesianGrid, ReferenceArea, XAxis, YAxis } from "recharts"
import { ChartContainer, ChartTooltip, ChartTooltipContent, type ChartConfig } from "@/components/ui/chart"
import { MIN, type AuditEvent, type Gap } from "@/data"
import { fmtHM } from "@/lib/format"
import type { Filters } from "@/lib/filters"
import { since } from "@/lib/filters"
import { usePan } from "@/lib/pan"

// 시리즈 순서 고정: ALLOW → WOULD_DENY → DENY. 필터가 바뀌어도 색은 따라가지 않는다.
const config = {
  ALLOW: { label: "ALLOW", color: "var(--v-allow)" },
  WOULD_DENY: { label: "WOULD_DENY (dry-run)", color: "var(--v-would)" },
  DENY: { label: "DENY (enforce)", color: "var(--v-deny)" },
} satisfies ChartConfig

/** 5분 버킷 스택 막대. 한 축, 유실 구간은 빗금 띠. */
export function TimelineChart({ filters, events, gaps, onPan }: { filters: Filters; events: AuditEvent[]; gaps: Gap[]; onPan: (dt: number) => void }) {
  // 그림을 끌거나 좌우로 스크롤하면 시간 창이 따라 움직인다. 오른쪽으로 끌면 과거.
  const panRef = usePan<HTMLDivElement>({ onPan, dragSign: -1, msPerPx: (el) => (filters.range * MIN) / Math.max(1, el.clientWidth - 52) })
  const bucket = 5 * MIN, n = (filters.range * MIN) / bucket, t0 = since(filters)
  const rows = Array.from({ length: n }, (_, i) => ({ t: t0 + i * bucket, label: fmtHM(t0 + i * bucket), ALLOW: 0, WOULD_DENY: 0, DENY: 0 }))
  // 집계 행과 무영장 귀속 기록(판정 없음)은 판정 추이에 넣지 않는다
  events.forEach((e) => { if (e.hook === "agg" || !e.warrant) return; rows[Math.min(n - 1, Math.floor((e.ts - t0) / bucket))][e.verdict]++ })
  const bucketOf = (t: number) => rows[Math.max(0, Math.min(n - 1, Math.floor((Math.min(t, filters.until) - t0) / bucket)))].label

  return (
    <div ref={panRef} className="cursor-grab touch-pan-y select-none data-[dragging]:cursor-grabbing">
    <ChartContainer config={config} className="h-[240px] w-full">
      <BarChart data={rows} barCategoryGap="15%" margin={{ top: 4, right: 8, left: -18, bottom: 0 }}>
        <defs>
          <pattern id="hatch" width="6" height="6" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
            <line x1="0" y1="0" x2="0" y2="6" stroke="var(--gap-ink)" strokeWidth="1.2" />
          </pattern>
        </defs>
        <CartesianGrid vertical={false} stroke="var(--border)" strokeDasharray="2 3" />
        <XAxis dataKey="label" tickLine={false} axisLine={false} interval="preserveStartEnd" minTickGap={18} tick={{ fontSize: 10.5, fontFamily: "var(--font-mono)", fill: "var(--muted-foreground)" }} />
        <YAxis tickLine={false} axisLine={false} allowDecimals={false} width={44} tick={{ fontSize: 10.5, fontFamily: "var(--font-mono)", fill: "var(--muted-foreground)" }} />
        {gaps.map((g) => (
          <ReferenceArea key={`${g.node}${g.seq_from}`} x1={bucketOf(g.from)} x2={bucketOf(g.to)} fill="url(#hatch)" stroke="var(--gap-ink)" strokeDasharray="2 3" ifOverflow="extendDomain" />
        ))}
        <ChartTooltip cursor={{ fill: "var(--muted)", fillOpacity: 0.6 }} content={<ChartTooltipContent labelFormatter={(l) => `${l} – 5분`} />} />
        {/* 쌓인 조각 사이는 카드 색 1px 테두리로 띄운다. 범례는 카드 머리에 있다. */}
        <Bar dataKey="ALLOW" stackId="v" isAnimationActive={false} fill="var(--color-ALLOW)" stroke="var(--card)" strokeWidth={0.75} />
        <Bar dataKey="WOULD_DENY" stackId="v" isAnimationActive={false} fill="var(--color-WOULD_DENY)" stroke="var(--card)" strokeWidth={0.75} />
        <Bar dataKey="DENY" stackId="v" isAnimationActive={false} fill="var(--color-DENY)" stroke="var(--card)" strokeWidth={0.75} radius={[2, 2, 0, 0]} />
      </BarChart>
    </ChartContainer>
    </div>
  )
}
