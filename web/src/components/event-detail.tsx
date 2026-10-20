import { Card, CardContent, CardHeader, CardTitle, CardAction } from "@/components/ui/card"
import { Separator } from "@/components/ui/separator"
import { VerdictPill, ModeChip, NoWarrantChip, UnjudgedPill } from "@/components/pills"
import { HOOKS, NOW, subjects, warrantById, type AuditEvent } from "@/data"
import { fmtN, fmtT, subjName } from "@/lib/format"
import { cn } from "@/lib/utils"

function KV({ rows }: { rows: [string, React.ReactNode, boolean?][] }) {
  return (
    <dl className="grid grid-cols-[96px_1fr] gap-x-2.5 gap-y-1 text-xs">
      {rows.map(([k, v, sans]) => (<div key={k} className="contents"><dt className="text-muted-foreground">{k}</dt><dd className={cn("break-all", !sans && "font-mono")}>{v}</dd></div>))}
    </dl>
  )
}
const Note = ({ children, warn }: { children: React.ReactNode; warn?: boolean }) => (
  <div className={cn("rounded-md px-2.5 py-2 text-xs leading-snug", warn ? "bg-warn-wash text-warn" : "bg-muted text-foreground/80")}>{children}</div>
)
const WASH = { ALLOW: "bg-allow-wash/60", WOULD_DENY: "bg-would-wash", DENY: "bg-deny-wash" }
const H = ({ children }: { children: React.ReactNode }) => <h3 className="mb-2 font-mono text-[10.5px] font-medium uppercase tracking-[.08em] text-muted-foreground">{children}</h3>

export function EventDetail({ e }: { e: AuditEvent | undefined }) {
  if (!e) {
    return (
      <Card className="sticky top-[84px] border-dashed bg-transparent shadow-none">
        <CardHeader><CardTitle className="text-sm">상세</CardTitle></CardHeader>
        <CardContent><div className="py-6 text-center text-sm text-muted-foreground">레코드를 고르세요</div></CardContent>
      </Card>
    )
  }
  const w = e.warrant ? warrantById[e.warrant] : null
  let payload: React.ReactNode
  if (e.hook === "exec") payload = <KV rows={[["filename", e.filename], ["dev · ino", `${e.dev} · ${fmtN(e.ino!)}`], ["interp", e.interp ?? "= filename"], ["setuid", e.setuid ? "S_ISUID" : "아니오"], ["argv", <span className="text-muted-foreground">{e.argv}</span>]]} />
  else if (e.hook === "write" || e.hook === "unlink" || e.hook === "rename") payload = <KV rows={[["path", e.path], ["dev · ino", `${e.dev} · ${fmtN(e.ino!)}`], ["parent ino", fmtN(e.parent_ino!)], ["f_flags", e.flags ?? "—"]]} />
  else if (e.hook === "connect") payload = <KV rows={[["family", e.family], [e.family === "AF_UNIX" ? "sun_path" : "addr", e.addr], ["port", e.family === "AF_UNIX" ? "—" : e.port]]} />
  else if (e.hook === "agg") payload = <KV rows={[["count", fmtN(e.count!)], ["window", e.window]]} />
  else payload = <Note>{e.note}</Note>

  return (
    <Card className="sticky top-[84px] gap-4 overflow-hidden pt-0">
      <CardHeader className={cn("border-b py-3.5 [.border-b]:pb-3.5", e.warrant ? WASH[e.verdict] : "bg-muted/60")}>
        <CardTitle className="flex min-w-0 items-center gap-2 text-sm">{e.warrant ? <VerdictPill v={e.verdict} /> : <UnjudgedPill />}<span className="truncate font-mono text-[12.5px] font-normal [overflow-wrap:normal]" title={HOOKS[e.hook]}>{HOOKS[e.hook]}</span></CardTitle>
        <CardAction className="font-mono text-xs text-muted-foreground">{fmtT(e.ts)}</CardAction>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <div><H>귀속</H><KV rows={[
          ["주체", w ? <>{subjName(e.subject)} <span className="text-muted-foreground">({subjects[e.subject!].email})</span></> : <NoWarrantChip />, true],
          ["영장", w ? <span className="flex items-center gap-1.5">{w.id} <ModeChip mode={w.mode} /></span> : "—", true],
          ["정책", w ? `write ${w.policy.write.join(", ") || "없음"} · exec ${w.policy.exec}` : "—", true],
          ["cgroup_id", <>{e.cgroup}{w && <span className="text-muted-foreground"> ({w.session})</span>}</>],
          ["node · seq", `${e.node} · ${fmtN(e.seq)}`],
        ]} /></div>
        <Separator />
        <div><H>프로세스</H><KV rows={[
          ["pid · tgid", `${e.pid} · ${e.tgid}`],
          ["start_time", `${fmtN(Math.round((e.start_time - (NOW - 90 * 24 * 3600 * 1000)) / 1000))}s (boot)`],
          ["ppid", String(e.ppid)],
          ["uid → euid", `${e.uid} → ${e.euid}`],
          ["comm", <span className="text-muted-foreground">{e.comm}</span>],
          ["pid ns · mnt ns", `${e.pid_ns} · ${e.mnt_ns}`],
        ]} /></div>
        <Separator />
        <div><H>페이로드</H>{payload}</div>
      </CardContent>
    </Card>
  )
}
