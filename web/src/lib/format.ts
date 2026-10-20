import { NOW, MIN, subjects } from "@/data"

const pad = (n: number) => String(n).padStart(2, "0")
export const fmtT = (ts: number) => { const d = new Date(ts); return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}` }
export const fmtHM = (ts: number) => { const d = new Date(ts); return `${pad(d.getHours())}:${pad(d.getMinutes())}` }
export const fmtMD = (ts: number) => { const d = new Date(ts); return `${pad(d.getMonth() + 1)}.${pad(d.getDate())}` }
export const fmtDur = (m: number) => (m < 60 ? `${m}분` : `${m / 60}시간`)
export const fmtN = (n: number) => n.toLocaleString("ko-KR")
export const rel = (ts: number) => {
  const m = Math.round((NOW - ts) / MIN)
  return m === 0 ? "방금" : m < 0 ? `${-m}분 후` : m < 60 ? `${m}분 전` : `${Math.floor(m / 60)}시간 ${m % 60}분 전`
}
export const subjName = (id: number | null) => (id != null && subjects[id] ? subjects[id].name : null)
export const VERD_KO: Record<string, string> = { ALLOW: "허용", WOULD_DENY: "차단 예정(dry-run)", DENY: "차단" }
