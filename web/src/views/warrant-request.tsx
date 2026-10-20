import { useState } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import { Deed, StatusBadge } from "@/components/warrant-card"
import { LintList } from "@/components/lint-list"
import { EXEC_PRESETS, NOW, MIN, nodes, subjects, type Mode, type OnExpiry, type Warrant, type WarrantRequest } from "@/data"
import { lintPolicy } from "@/lib/lint"
import { fmtDur } from "@/lib/format"
import { X } from "lucide-react"

const DURATIONS = [30, 60, 120, 240]
const isPath = (s: string) => /^\/[^\s]*$/.test(s) && !s.includes("//")
const isCidr = (s: string) => /^(\d{1,3})(\.\d{1,3}){3}\/(\d|[12]\d|3[0-2])$/.test(s) && s.split("/")[0].split(".").every((o) => +o <= 255)

/** 경로 · CIDR 목록 입력 — Enter 로 추가, × 로 제거 */
function ListInput({ items, setItems, valid, placeholder, invalidMsg }: {
  items: string[]; setItems: (v: string[]) => void; valid: (s: string) => boolean; placeholder: string; invalidMsg: string
}) {
  const [v, setV] = useState("")
  const t = v.trim()
  const bad = t !== "" && !valid(t)
  const add = () => { if (t && !bad && !items.includes(t)) { setItems([...items, t]); setV("") } }
  return (
    <div className="flex flex-col gap-1.5">
      {items.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {items.map((p) => (
            <span key={p} className="inline-flex items-center gap-1 rounded-[4px] border bg-muted px-1.5 py-0.5 font-mono text-[12px]">
              {p}
              <button type="button" onClick={() => setItems(items.filter((x) => x !== p))} aria-label={`${p} 제거`} className="rounded-sm text-muted-foreground hover:bg-accent hover:text-foreground"><X className="size-3" /></button>
            </span>
          ))}
        </div>
      )}
      <div className="flex gap-2">
        <Input value={v} onChange={(e) => setV(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); add() } }}
          placeholder={placeholder} aria-invalid={bad} className="h-8 font-mono text-xs" />
        <Button type="button" variant="outline" size="sm" className="h-8" disabled={!t || bad} onClick={add}>추가</Button>
      </div>
      {bad && <span className="text-xs text-deny">{invalidMsg}</span>}
    </div>
  )
}

// 렌더 밖에 둔다 — 안에서 만들면 입력할 때마다 칸이 새로 생겨 포커스를 잃는다
function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid gap-1.5 sm:grid-cols-[96px_minmax(0,1fr)] sm:items-start sm:gap-3">
      <div className="pt-1.5 text-[13px] font-medium text-ink-2">{label}</div>
      <div className="min-w-0">{children}</div>
    </div>
  )
}

export function WarrantRequestView({ me, nextId, onSubmit }: { me: number; nextId: () => string; onSubmit: (r: WarrantRequest) => void }) {
  const [node, setNode] = useState(Object.keys(nodes)[0])
  const [reason, setReason] = useState("")
  const [minutes, setMinutes] = useState(60)
  const [mode, setMode] = useState<Mode>("dryrun")
  const [onExpiry, setOnExpiry] = useState<OnExpiry>("downgrade")
  const [write, setWrite] = useState<string[]>([])
  const [exec, setExec] = useState(EXEC_PRESETS[1])
  const [net, setNet] = useState<string[]>([])

  const policy = { write, exec, net }
  const lint = lintPolicy({ node, mode, policy, minutes })
  const ok = reason.trim().length >= 4
  const preview: Warrant = { id: "신규", subject: me, node, mode, on_expiry: onExpiry, reason: reason.trim() || "—", policy, issued: NOW, expires: NOW + minutes * MIN, cgroup: 0, session: "", lineage: [] }

  const submit = () => {
    if (!ok) return
    onSubmit({ id: nextId(), requester: me, node, reason: reason.trim(), minutes, mode, on_expiry: onExpiry, policy, requested: NOW, status: "pending" })
  }

  return (
    <div className="grid items-start gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
      <Card className="gap-5">
        <CardHeader><CardTitle className="text-sm">신청</CardTitle></CardHeader>
        <CardContent className="flex flex-col gap-4">
          <Row label="신청자"><div className="pt-1.5 text-sm">{subjects[me].name} <span className="font-mono text-xs text-muted-foreground">{subjects[me].email}</span></div></Row>
          <Row label="대상 노드">
            <Select value={node} onValueChange={setNode}>
              <SelectTrigger size="sm" className="w-full font-mono text-xs sm:w-[240px]"><SelectValue /></SelectTrigger>
              <SelectContent>{Object.keys(nodes).map((n) => <SelectItem key={n} value={n} className="font-mono text-xs">{n} · {nodes[n].mode}</SelectItem>)}</SelectContent>
            </Select>
          </Row>
          <Row label="사유">
            <Input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="INC-0000 · 작업 내용" className="h-8" />
          </Row>
          <Row label="기간">
            <ToggleGroup type="single" variant="outline" size="sm" value={String(minutes)} onValueChange={(v) => { if (v) setMinutes(Number(v)) }}>
              {DURATIONS.map((d) => <ToggleGroupItem key={d} value={String(d)} className="px-3 font-mono text-xs">{fmtDur(d)}</ToggleGroupItem>)}
            </ToggleGroup>
          </Row>
          <Row label="모드">
            <ToggleGroup type="single" variant="outline" size="sm" value={mode} onValueChange={(v) => { if (v) setMode(v as Mode) }}>
              {(["observe", "dryrun", "enforce"] as const).map((m) => <ToggleGroupItem key={m} value={m} className="px-3 font-mono text-xs">{m}</ToggleGroupItem>)}
            </ToggleGroup>
          </Row>
          <Row label="만료 시">
            <ToggleGroup type="single" variant="outline" size="sm" value={onExpiry} onValueChange={(v) => { if (v) setOnExpiry(v as OnExpiry) }}>
              {([["downgrade", "강등"], ["kill", "종료"], ["grace", "유예"]] as const).map(([k, l]) => <ToggleGroupItem key={k} value={k} className="px-3 text-xs">{l}</ToggleGroupItem>)}
            </ToggleGroup>
          </Row>
          <Row label="쓰기 허용"><ListInput items={write} setItems={setWrite} valid={isPath} placeholder="/app" invalidMsg="절대 경로가 아님" /></Row>
          <Row label="실행 허용">
            <Select value={exec} onValueChange={setExec}>
              <SelectTrigger size="sm" className="w-full text-xs sm:w-[280px]"><SelectValue /></SelectTrigger>
              <SelectContent>{EXEC_PRESETS.map((p) => <SelectItem key={p} value={p} className="text-xs">{p}</SelectItem>)}</SelectContent>
            </Select>
          </Row>
          <Row label="네트워크 허용"><ListInput items={net} setItems={setNet} valid={isCidr} placeholder="10.0.0.0/8" invalidMsg="CIDR 형식이 아님" /></Row>
        </CardContent>
      </Card>

      <div className="flex flex-col gap-4">
        <Deed w={preview} badge={<StatusBadge label="초안" tone="pending" />} validity={<span className="font-mono">{fmtDur(minutes)}</span>}
          foot={<><span>신청 {subjects[me].name}</span><span>승인 필요</span></>} />
        <Card className="gap-3">
          <CardHeader><CardTitle className="text-sm">정책 검사</CardTitle></CardHeader>
          <CardContent><LintList lint={lint} /></CardContent>
        </Card>
        <div className="flex justify-end">
          <Button disabled={!ok} onClick={submit} className="h-9 px-5">승인 요청</Button>
        </div>
      </div>
    </div>
  )
}
