import type { Lint } from "@/lib/lint"
import { cn } from "@/lib/utils"
import { TriangleAlert, OctagonAlert, Check } from "lucide-react"

/** 정책 lint 결과 — 아이콘 + 글자. 색만으로 등급을 싣지 않는다 */
export function LintList({ lint }: { lint: Lint[] }) {
  if (!lint.length) return <div className="flex items-center gap-1.5 text-sm text-muted-foreground"><Check className="size-4" />경고 없음</div>
  return (
    <ul className="flex flex-col gap-1.5">
      {lint.map((l) => {
        const Icon = l.level === "crit" ? OctagonAlert : TriangleAlert
        return (
          <li key={l.text} className={cn("flex items-start gap-2 rounded-md px-2.5 py-1.5 text-[13px]", l.level === "crit" ? "bg-deny-wash text-deny" : "bg-warn-wash text-warn")}>
            <Icon className="mt-0.5 size-4 shrink-0" /><span>{l.text}</span>
          </li>
        )
      })}
    </ul>
  )
}

/** 목록용 요약 칩 — 위험 n · 주의 n */
export function LintCount({ lint }: { lint: Lint[] }) {
  const c = lint.filter((l) => l.level === "crit").length, w = lint.length - c
  return (
    <span className="flex items-center gap-1">
      {c > 0 && <span className="flex items-center gap-1 rounded bg-deny-wash px-1.5 font-mono text-[11px] font-semibold leading-5 text-deny"><OctagonAlert className="size-3" />{c}</span>}
      {w > 0 && <span className="flex items-center gap-1 rounded bg-warn-wash px-1.5 font-mono text-[11px] font-semibold leading-5 text-warn"><TriangleAlert className="size-3" />{w}</span>}
    </span>
  )
}
