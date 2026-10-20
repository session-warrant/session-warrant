import { useState } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Checkbox } from "@/components/ui/checkbox"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import { Deed, StatusBadge } from "@/components/warrant-card"
import { LintCount, LintList } from "@/components/lint-list"
import { ModeChip } from "@/components/pills"
import { MIN, subjects, type Warrant, type WarrantRequest } from "@/data"
import { lintPolicy } from "@/lib/lint"
import { fmtDur, fmtHM, rel } from "@/lib/format"
import { cn } from "@/lib/utils"
import { ArrowRight } from "lucide-react"

interface Props {
  requests: WarrantRequest[]; me: number
  selected: string | null; setSelected: (id: string) => void
  onApprove: (id: string) => void; onReject: (id: string, reason: string) => void
  onOpenWarrant: (id: string) => void
}

const BADGE = { pending: ["승인 대기", "pending"], approved: ["발급됨", "active"], rejected: ["반려", "rejected"] } as const

export function ApprovalQueue({ requests, me, selected, setSelected, onApprove, onReject, onOpenWarrant }: Props) {
  const [tab, setTab] = useState<"pending" | "done">(() => requests.find((r) => r.id === selected)?.status === "pending" || !selected ? "pending" : "done")
  const pending = requests.filter((r) => r.status === "pending").sort((a, b) => a.requested - b.requested)
  const done = requests.filter((r) => r.status !== "pending").sort((a, b) => (b.decided ?? 0) - (a.decided ?? 0))
  const list = tab === "pending" ? pending : done
  const r = list.find((x) => x.id === selected) ?? list[0]

  return (
    <div className="flex flex-col gap-4">
      <ToggleGroup type="single" variant="outline" size="sm" value={tab} onValueChange={(v) => { if (v) setTab(v as typeof tab) }} className="self-start">
        <ToggleGroupItem value="pending" className="gap-1.5 px-3 text-xs">대기 <span className="font-mono">{pending.length}</span></ToggleGroupItem>
        <ToggleGroupItem value="done" className="gap-1.5 px-3 text-xs">처리됨 <span className="font-mono">{done.length}</span></ToggleGroupItem>
      </ToggleGroup>

      <div className="grid items-start gap-4 xl:grid-cols-[minmax(0,5fr)_minmax(0,6fr)]">
        <div className="flex flex-col gap-2" role="listbox" aria-label="요청">
          {list.length ? list.map((x) => {
            const on = r?.id === x.id
            return (
              <button key={x.id} role="option" aria-selected={on} onClick={() => setSelected(x.id)}
                className={cn("grid grid-cols-[minmax(0,1fr)_auto] gap-x-3 gap-y-1 rounded-md border bg-card px-3.5 py-3 text-left transition-colors hover:bg-muted focus-visible:outline-2 focus-visible:outline-ring",
                  on && "border-foreground ring-1 ring-foreground hover:bg-card")}>
                <span className="flex min-w-0 items-center gap-2">
                  <span className="font-mono text-[13px] font-semibold">{x.id}</span>
                  {x.requester === me && <span className="rounded border border-dashed border-foreground/40 px-1 text-[10.5px] font-medium">본인</span>}
                </span>
                <span className="flex items-center gap-2">
                  <LintCount lint={lintPolicy(x)} />
                  {x.status !== "pending" && <StatusBadge label={BADGE[x.status][0]} tone={BADGE[x.status][1]} />}
                </span>
                <span className="col-span-2 truncate text-[13px]">{x.reason}</span>
                <span className="col-span-2 flex flex-wrap items-center gap-x-2 gap-y-1 font-mono text-[11px] text-muted-foreground">
                  <span className="text-ink-2">{subjects[x.requester].name}</span>
                  <span>{x.node}</span><span>{fmtDur(x.minutes)}</span><ModeChip mode={x.mode} />
                  <span className="ml-auto">{x.status === "pending" ? rel(x.requested) : fmtHM(x.decided!)}</span>
                </span>
              </button>
            )
          }) : <Card><CardContent className="py-8 text-center text-sm text-muted-foreground">없음</CardContent></Card>}
        </div>

        {r && <Detail key={r.id} r={r} me={me} onApprove={onApprove} onReject={onReject} onOpenWarrant={onOpenWarrant} />}
      </div>
    </div>
  )
}

function Detail({ r, me, onApprove, onReject, onOpenWarrant }: { r: WarrantRequest; me: number } & Pick<Props, "onApprove" | "onReject" | "onOpenWarrant">) {
  const [reason, setReason] = useState("")
  const [ack, setAck] = useState(false)
  const lint = lintPolicy(r)
  const crit = lint.some((l) => l.level === "crit")
  const canDecide = !!subjects[me].approver && r.requester !== me
  const w: Warrant = { id: r.id, subject: r.requester, node: r.node, mode: r.mode, on_expiry: r.on_expiry, reason: r.reason, policy: r.policy, issued: r.requested, expires: r.requested + r.minutes * MIN, cgroup: 0, session: "", lineage: [] }

  return (
    <div className="flex flex-col gap-4 xl:sticky xl:top-[84px]">
      <Deed w={w} badge={<StatusBadge label={BADGE[r.status][0]} tone={BADGE[r.status][1]} />}
        validity={<span className="font-mono">{fmtDur(r.minutes)}</span>}
        foot={<><span>신청 {subjects[r.requester].name} · {fmtHM(r.requested)}</span>{r.decidedBy && <span>{r.status === "approved" ? "승인" : "반려"} {subjects[r.decidedBy].name} · {fmtHM(r.decided!)}</span>}</>} />

      <Card className="gap-3">
        <CardHeader><CardTitle className="text-sm">정책 검사</CardTitle></CardHeader>
        <CardContent><LintList lint={lint} /></CardContent>
      </Card>

      {r.status === "pending" && (
        <Card className="gap-3">
          <CardContent className="flex flex-col gap-3">
            {!subjects[me].approver ? <span className="text-sm text-muted-foreground">승인 권한 없음</span>
              : r.requester === me ? <span className="text-sm text-muted-foreground">본인 신청은 승인할 수 없음</span>
              : (<>
                {crit && (
                  <label className="flex items-center gap-2 text-sm">
                    <Checkbox checked={ack} onCheckedChange={(c) => setAck(c === true)} />위험 경고 확인
                  </label>
                )}
                <div className="flex flex-wrap items-center gap-2">
                  <Button onClick={() => onApprove(r.id)} disabled={crit && !ack} className="h-9 px-5">승인 · 발급</Button>
                  <div className="ml-auto flex min-w-[240px] flex-1 gap-2 sm:flex-none">
                    <Input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="반려 사유" className="h-9" />
                    <Button variant="outline" className="h-9" disabled={!reason.trim() || !canDecide} onClick={() => onReject(r.id, reason.trim())}>반려</Button>
                  </div>
                </div>
              </>)}
          </CardContent>
        </Card>
      )}
      {r.status === "rejected" && r.rejectReason && (
        <Card className="gap-2"><CardContent className="text-sm"><span className="mr-2 font-medium text-deny">반려 사유</span>{r.rejectReason}</CardContent></Card>
      )}
      {r.status === "approved" && (
        <Button variant="outline" className="h-9 self-end" onClick={() => onOpenWarrant(r.id)}>세션 타임라인<ArrowRight className="size-4" /></Button>
      )}
    </div>
  )
}
