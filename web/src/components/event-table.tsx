import { useEffect, useRef } from "react"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { VerdictPill, NoWarrantChip, UnjudgedPill } from "@/components/pills"
import { HOOKS, type AuditEvent, type Gap } from "@/data"
import { fmtN, fmtT, subjName } from "@/lib/format"
import { cn } from "@/lib/utils"

function What({ e }: { e: AuditEvent }) {
  switch (e.hook) {
    case "exec": {
      const flags = [e.setuid ? "setuid" : null, e.interp ? `interp ${e.interp}` : null].filter(Boolean).join(" · ")
      return (
        <div className="min-w-[220px] break-all">
          <div className="font-mono text-xs">{e.filename}</div>
          <div className="font-mono text-[11px] text-muted-foreground">dev {e.dev} · ino {fmtN(e.ino!)}{flags ? ` · ${flags}` : ""}</div>
          <div className="text-xs text-muted-foreground/85"><span className="text-[10px] uppercase tracking-wider">argv </span>{e.argv}</div>
        </div>
      )
    }
    case "write": case "unlink": case "rename":
      return (
        <div className="min-w-[220px] break-all">
          <div className="font-mono text-xs">{e.path}</div>
          <div className="font-mono text-[11px] text-muted-foreground">dev {e.dev} · ino {fmtN(e.ino!)} · 부모 ino {fmtN(e.parent_ino!)}{e.flags ? ` · ${e.flags}` : ""}</div>
        </div>
      )
    case "connect":
      return (
        <div className="min-w-[220px] break-all">
          <div className="font-mono text-xs">{e.family === "AF_UNIX" ? e.addr : `${e.addr}:${e.port}`}</div>
          <div className="font-mono text-[11px] text-muted-foreground">{e.family}</div>
        </div>
      )
    case "agg":
      return <div>허용 쓰기 <b className="tabular-nums">{fmtN(e.count!)}</b>건 / {e.window}</div>
    case "self":
      return <div>{e.note}</div>
  }
}

// 훅 열은 lsm/ 접두사를 떼고 보여준다. 전체 이름은 상세 패널에 있다.
const hookName = (h: AuditEvent["hook"]) => HOOKS[h].replace(/^lsm\//, "")

// 차단 행은 왼쪽 끝에 판정색 띠를 둔다. 허용 행은 띠 없음.
const STRIPE = { ALLOW: "", WOULD_DENY: "shadow-[inset_3px_0_0_var(--v-would)]", DENY: "shadow-[inset_3px_0_0_var(--v-deny)]" }

interface Props {
  events: AuditEvent[]
  gaps: Gap[]
  selectedId?: string | null
  onSelect: (id: string) => void
  emptyMsg?: string
}

/** 이벤트와 유실 구간을 시간순으로 섞어 표를 만든다. 유실 구간은 숨기지 않는다. */
export function EventTable({ events, gaps, selectedId, onSelect, emptyMsg = "해당하는 이벤트가 없습니다" }: Props) {
  type Item = { t: number; key: string; node: React.ReactNode }
  const items: Item[] = [
    ...events.map((e): Item => ({
      t: e.ts, key: e.id,
      node: (
        <TableRow
          key={e.id} data-id={e.id} tabIndex={0} data-state={selectedId === e.id ? "selected" : undefined}
          className={cn("cursor-pointer focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-ring data-[state=selected]:bg-accent data-[state=selected]:hover:bg-accent", e.hook === "agg" && "text-muted-foreground")}
          onClick={() => onSelect(e.id)} onKeyDown={(k) => { if (k.key === "Enter") onSelect(e.id) }}
        >
          <TableCell className={cn("whitespace-nowrap", e.warrant && STRIPE[e.verdict])}>
            <div className={cn("font-mono text-xs", selectedId === e.id ? "font-semibold text-foreground" : "text-muted-foreground")}>{fmtT(e.ts)}</div>
            <div className="font-mono text-[11px] text-muted-foreground">{e.node}</div>
          </TableCell>
          <TableCell className="whitespace-nowrap">
            {e.warrant ? <VerdictPill v={e.verdict} /> : <UnjudgedPill />}
            <div className="mt-1 font-mono text-[11px] text-muted-foreground">{hookName(e.hook)}</div>
          </TableCell>
          <TableCell className="whitespace-nowrap">
            {e.warrant ? (<>{subjName(e.subject)}<br /><span className="font-mono text-[11px] text-muted-foreground">{e.warrant}</span></>)
              : (<><NoWarrantChip /><br /><span className="font-mono text-[11px] text-muted-foreground">cgroup {e.cgroup}</span></>)}
          </TableCell>
          <TableCell className="w-full"><What e={e} /></TableCell>
          <TableCell className="font-mono text-[11px] text-muted-foreground whitespace-nowrap">pid {e.pid}<br />uid {e.uid}→<span className={cn(e.euid === 0 && e.uid !== 0 && "font-semibold text-warn")}>{e.euid}</span></TableCell>
        </TableRow>
      ),
    })),
    ...gaps.map((g): Item => ({
      t: g.from, key: `gap-${g.node}-${g.seq_from}`,
      node: (
        <TableRow key={`gap-${g.node}-${g.seq_from}`} className="hover:bg-transparent">
          <TableCell colSpan={5} className="hatch text-xs text-muted-foreground shadow-[inset_3px_0_0_var(--gap-ink)]">
            <b className="text-foreground">감사 유실 구간</b> · {g.node} · {fmtT(g.from)} – {fmtT(g.to)} · seq {fmtN(g.seq_from)} → {fmtN(g.seq_to)} · <b className="text-foreground">dropped {fmtN(g.dropped)}</b> · {g.cause}
          </TableCell>
        </TableRow>
      ),
    })),
  ].sort((a, b) => b.t - a.t)

  // 다른 화면에서 레코드를 열고 왔을 때 그 행이 보이게 한다. 화면 전환의 맨 위 스크롤보다 늦게 돌도록 한 프레임 미룬다.
  const body = useRef<HTMLTableSectionElement>(null)
  useEffect(() => {
    if (!selectedId) return
    const id = requestAnimationFrame(() => {
      const row = body.current?.querySelector(`[data-id="${CSS.escape(selectedId)}"]`)
      if (!row) return
      const r = row.getBoundingClientRect()
      // 고정 헤더(약 90px) 아래로 이미 보이면 건드리지 않는다 — 클릭할 때마다 화면이 튀지 않게
      if (r.top < 90 || r.bottom > window.innerHeight) row.scrollIntoView({ block: "center" })
    })
    return () => cancelAnimationFrame(id)
  }, [selectedId])

  if (!items.length) return <div className="p-8 text-center text-sm text-muted-foreground">{emptyMsg}</div>
  return (
    <div className="overflow-x-auto">
      <Table>
        <TableHeader>
          <TableRow className="bg-muted/50 hover:bg-muted/50 [&_th]:h-8 [&_th]:font-mono [&_th]:text-[10.5px] [&_th]:font-medium [&_th]:uppercase [&_th]:tracking-[.06em] [&_th]:text-muted-foreground">
            <TableHead>시각 · 노드</TableHead><TableHead>판정 · 훅</TableHead><TableHead>주체 · 영장</TableHead>
            <TableHead>대상</TableHead><TableHead>프로세스</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody ref={body} className="text-[12.5px] [&_td]:py-2.5 [&_td]:align-top">{items.map((i) => i.node)}</TableBody>
      </Table>
    </div>
  )
}
