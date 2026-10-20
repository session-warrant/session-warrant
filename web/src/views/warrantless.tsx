import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { EventTable } from "@/components/event-table"
import { SeverityChip } from "@/components/pills"
import { events } from "@/data"
import { warrantlessIn, type Filters } from "@/lib/filters"
import { fmtT, rel } from "@/lib/format"
import { cn } from "@/lib/utils"

interface Props { filters: Filters; selected: number | null; setSelected: (cg: number) => void; onOpenEvent: (id: string) => void }

export function Warrantless({ filters, selected, setSelected, onOpenEvent }: Props) {
  const wl = warrantlessIn(filters)
  const s = wl.find((x) => x.cgroup === selected) ?? wl[0]
  const ev = s ? events.filter((e) => e.warrant === null && e.cgroup === s.cgroup) : []
  return (
    <div className="flex flex-col gap-4">
      <Card className="gap-4 pb-0">
        <CardHeader><CardTitle className="text-sm">영장 없이 열린 세션</CardTitle></CardHeader>
        {wl.length ? (
          <div className="overflow-x-auto">
            <Table>
              <TableHeader><TableRow className="bg-muted/50 hover:bg-muted/50 [&_th]:h-8 [&_th]:font-mono [&_th]:text-[10.5px] [&_th]:font-medium [&_th]:uppercase [&_th]:tracking-[.06em] [&_th]:text-muted-foreground"><TableHead>등급</TableHead><TableHead>노드</TableHead><TableHead>세션 · cgroup</TableHead><TableHead>uid</TableHead><TableHead>출발지</TableHead><TableHead>시작</TableHead><TableHead>귀속 이벤트</TableHead><TableHead>왜 무영장인가</TableHead></TableRow></TableHeader>
              <TableBody className="text-[12.5px] [&_td]:py-2.5">
                {wl.map((x) => (
                  <TableRow key={x.cgroup} tabIndex={0} className="cursor-pointer focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-ring data-[state=selected]:bg-accent" data-state={s?.cgroup === x.cgroup ? "selected" : undefined}
                    onClick={() => setSelected(x.cgroup)} onKeyDown={(k) => { if (k.key === "Enter") setSelected(x.cgroup) }}>
                    <TableCell className={x.severity === "critical" ? "shadow-[inset_3px_0_0_var(--v-deny)]" : "shadow-[inset_3px_0_0_var(--warn)]"}><SeverityChip s={x.severity} /></TableCell>
                    <TableCell className="font-mono text-xs">{x.node}</TableCell>
                    <TableCell className="font-mono text-xs">{x.session} · {x.cgroup}</TableCell>
                    <TableCell className="font-mono text-xs">{x.uid}{x.uid === 0 && <span className="ml-1 rounded bg-deny-wash px-1 text-[10.5px] font-semibold text-deny">root</span>}</TableCell>
                    <TableCell className="font-mono text-xs">{x.from}</TableCell>
                    <TableCell className="font-mono text-xs whitespace-nowrap">{fmtT(x.first)} <span className="text-muted-foreground">{rel(x.first)}</span></TableCell>
                    <TableCell className="tabular-nums">{x.count}</TableCell>
                    <TableCell>{x.reason}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        ) : <div className="p-8 text-center text-sm text-muted-foreground">없음</div>}
      </Card>
      <Card className="gap-4 pb-0">
        <CardHeader><CardTitle className="text-sm">세션 안에서 일어난 일</CardTitle>{s && <CardDescription className="font-mono text-xs">{ev.length}건</CardDescription>}</CardHeader>
        {s && (
          <dl className={cn("mx-6 grid grid-cols-2 gap-x-6 gap-y-2.5 rounded-md border border-l-[3px] bg-muted/40 px-4 py-3 text-xs sm:grid-cols-3 xl:grid-cols-6", s.severity === "critical" ? "border-l-deny" : "border-l-warn")}>
            {([
              ["노드", s.node], ["세션", s.session], ["cgroup", String(s.cgroup)],
              ["uid", s.uid === 0 ? "0 (root)" : String(s.uid)], ["출발지", s.from], ["시작", `${fmtT(s.first)} · ${rel(s.first)}`],
            ] as const).map(([k, v]) => (
              <div key={k} className="min-w-0"><dt className="font-mono text-[10.5px] uppercase tracking-[.06em] text-muted-foreground">{k}</dt><dd className="font-mono text-[12.5px] [overflow-wrap:normal]">{v}</dd></div>
            ))}
            <div className="col-span-full flex items-center gap-2 border-t border-dashed pt-2.5"><SeverityChip s={s.severity} /><span className="text-ink-2">{s.reason}</span></div>
          </dl>
        )}
        <EventTable events={ev} gaps={[]} onSelect={onOpenEvent} />
      </Card>
    </div>
  )
}
