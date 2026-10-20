import { Card } from "@/components/ui/card"
import { ModeChip } from "@/components/pills"
import { NOW, MIN, subjects, type Warrant } from "@/data"
import { fmtHM, rel, subjName } from "@/lib/format"
import { cn } from "@/lib/utils"

export const ON = { downgrade: "강등", kill: "종료", grace: "유예" }
export const GRACE = 120 * MIN

export type Status = "active" | "grace" | "expired"
export const statusOf = (w: Warrant): Status => w.expires > NOW ? "active" : w.on_expiry === "grace" && w.expires + GRACE > NOW ? "grace" : "expired"
export const STATUS_KO: Record<Status, string> = { active: "유효", grace: "유예 중", expired: "만료" }

/** 영장 상태 배지 — 유효 · 유예 중 · 만료 */
export function StatusBadge({ label, tone }: { label: string; tone: "active" | "grace" | "expired" | "pending" | "rejected" }) {
  const cls = {
    active: "border-foreground/30 text-foreground",
    grace: "border-transparent bg-warn-wash text-warn",
    expired: "border-transparent bg-muted text-muted-foreground",
    pending: "border-dashed border-foreground/40 text-foreground",
    rejected: "border-transparent bg-deny-wash text-deny",
  }[tone]
  return (
    <span className={cn("inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border px-2.5 py-0.5 text-xs font-medium", cls)}>
      <span className="size-1.5 rounded-full bg-current" aria-hidden />
      {label}
    </span>
  )
}

export const Tok = ({ children }: { children: React.ReactNode }) => <span className="mr-1 rounded-[3px] bg-muted px-1.5 py-px font-mono text-[12px]">{children}</span>

/** 영장 카드. 신청 미리보기 · 승인 큐는 badge · validity · foot 을 바꿔 끼운다 */
export function Deed({ w, badge, validity, foot }: { w: Warrant; badge?: React.ReactNode; validity?: React.ReactNode; foot?: React.ReactNode }) {
  const approver = w.lineage.find((l) => l.kind === "승인")?.who
  const extended = w.lineage.filter((l) => l.kind.startsWith("연장")).length
  const row = (k: string, v: React.ReactNode) => (<div key={k} className="contents"><dt className="pt-px text-[12px] text-muted-foreground">{k}</dt><dd className="min-w-0">{v}</dd></div>)
  return (
    <Card className="gap-0 py-0">
      <div className="flex flex-wrap items-start justify-between gap-3 border-b px-6 py-4">
        <div>
          <div className="font-mono text-[10.5px] uppercase tracking-[.08em] text-muted-foreground">영장</div>
          <div className="mt-0.5 font-mono text-[18px] font-semibold tracking-tight">{w.id}</div>
        </div>
        {badge ?? <StatusBadge label={STATUS_KO[statusOf(w)]} tone={statusOf(w)} />}
      </div>
      <dl className="grid grid-cols-[64px_minmax(0,1fr)] gap-x-3.5 gap-y-2.5 px-6 py-4 text-[13.5px]">
        {row("주체", <>{subjName(w.subject)} <span className="text-[12px] text-muted-foreground">{subjects[w.subject].email} · {subjects[w.subject].team}</span></>)}
        {row("사유", w.reason)}
        {row("대상", <><Tok>{w.node}</Tok><span className="font-mono text-[12px] text-muted-foreground">{w.cgroup ? `${w.session} → cgroup ${w.cgroup}` : "바인딩 대기"}</span></>)}
        {row("유효", validity ?? <><span className="font-mono">{fmtHM(w.issued)} → {fmtHM(w.expires)}</span> <span className="text-[12px] text-muted-foreground">· {statusOf(w) === "active" ? `만료 ${rel(w.expires)}` : STATUS_KO[statusOf(w)]}{extended ? ` · 연장 ${extended}회` : ""}</span></>)}
        {row("쓰기", w.policy.write.length ? <>{w.policy.write.map((p) => <Tok key={p}>{p}</Tok>)}</> : <span className="text-muted-foreground">없음</span>)}
        {row("실행", w.policy.exec)}
        {row("네트워크", w.policy.net.length ? <>{w.policy.net.map((p) => <Tok key={p}>{p}</Tok>)}</> : <span className="text-muted-foreground">없음</span>)}
        {row("모드", <span className="flex flex-wrap items-center gap-1.5"><ModeChip mode={w.mode} /><span className="text-[12px] text-muted-foreground">만료 시 {ON[w.on_expiry]}</span></span>)}
      </dl>
      <div className="flex flex-wrap justify-between gap-2 border-t bg-muted/40 px-6 py-2.5 font-mono text-[11.5px] text-muted-foreground">
        {foot ?? <><span>승인 {approver ?? "—"} · 콘솔</span><span>Ed25519 서명 · 발급 {fmtHM(w.issued)}</span></>}
      </div>
    </Card>
  )
}

