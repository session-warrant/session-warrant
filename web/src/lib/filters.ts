import { NOW, MIN, events, gaps, warrants, warrantless, type AuditEvent, type Hook, type Verdict, type Warrant } from "@/data"
import { subjName } from "@/lib/format"

export type Range = 60 | 180 | 360
export interface Filters {
  range: Range
  node: string            // "all" | 노드명
  verdict: "all" | "blocked" | Verdict
  hook: "all" | Hook
  subject: "all" | "none" | string // subject id 문자열
  agg: boolean            // 집계 행 표시
  q: string
  until: number           // 보고 있는 창의 끝. 좌우 스크롤로 과거로 옮긴다
}
export const DEFAULT_FILTERS: Filters = { range: 360, node: "all", verdict: "all", hook: "all", subject: "all", agg: true, q: "", until: NOW }

/** 목 데이터가 덮는 기록 전체 — 창은 이 안에서만 움직인다 */
export const HISTORY_START = NOW - 24 * 60 * MIN
export const PAN_STEP = 5 * MIN
/** 창 끝을 5분 격자에 맞추고 기록 범위 안으로 가둔다 */
export const clampUntil = (t: number, range: Range) =>
  Math.min(NOW, Math.max(HISTORY_START + range * MIN, Math.round(t / PAN_STEP) * PAN_STEP))

export const since = (f: Filters) => f.until - f.range * MIN
export const blocked = (e: AuditEvent) => e.verdict === "DENY" || e.verdict === "WOULD_DENY"
const nodeOk = (f: Filters, node: string) => f.node === "all" || node === f.node

/** 기간·노드만 적용한 이벤트. 개요 화면의 모든 숫자가 여기서 나온다. */
export const baseEvents = (f: Filters) => events.filter((e) => e.ts >= since(f) && e.ts <= f.until && nodeOk(f, e.node))
export const gapsIn = (f: Filters) => gaps.filter((g) => g.to >= since(f) && g.from <= f.until && nodeOk(f, g.node))
export const warrantlessIn = (f: Filters) => warrantless.filter((s) => s.last >= since(f) && s.first <= f.until && nodeOk(f, s.node))
/** 창과 겹치는 영장 — 유예 기간까지 포함 */
export const warrantsIn = (f: Filters) => warrants.filter((w) => w.issued <= f.until && warrantEnd(w) >= since(f) && nodeOk(f, w.node))
export const warrantEnd = (w: Warrant) => w.on_expiry === "grace" ? w.expires + 120 * MIN : w.expires

/** 감사 검색 — 판정·훅·주체·텍스트까지 적용 */
export function searchEvents(f: Filters) {
  const q = f.q.trim().toLowerCase()
  return baseEvents(f).filter((e) => {
    if (f.verdict === "blocked" ? !blocked(e) : f.verdict !== "all" && e.verdict !== f.verdict) return false
    if (f.hook !== "all" && e.hook !== f.hook) return false
    if (f.subject === "none" ? e.warrant !== null : f.subject !== "all" && String(e.subject) !== f.subject) return false
    if (!f.agg && e.hook === "agg") return false
    if (q) {
      const hay = [e.filename, e.argv, e.path, e.addr, e.warrant, e.comm, e.ino, e.node, subjName(e.subject), e.note].filter(Boolean).join(" ").toLowerCase()
      if (!hay.includes(q)) return false
    }
    return true
  })
}
