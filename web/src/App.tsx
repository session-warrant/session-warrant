import { useEffect, useState } from "react"
import { Button } from "@/components/ui/button"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import { TooltipProvider } from "@/components/ui/tooltip"
import { Badge } from "@/components/ui/badge"
import { Label } from "@/components/label"
import { Overview } from "@/views/overview"
import { AuditSearch } from "@/views/audit-search"
import { WarrantTimeline } from "@/views/warrant-timeline"
import { Warrantless } from "@/views/warrantless"
import { MIN, NOW, events, issueWarrant, nextWarrantId, nodes, seedRequests, subjects, type WarrantRequest } from "@/data"
import { WarrantRequestView } from "@/views/warrant-request"
import { ApprovalQueue } from "@/views/approval-queue"
import { TimeNavigator } from "@/components/time-navigator"
import { DEFAULT_FILTERS, baseEvents, blocked, clampUntil, gapsIn, since, warrantlessIn, type Filters, type Range } from "@/lib/filters"
import { fmtHM, fmtMD, fmtN } from "@/lib/format"
import { cn } from "@/lib/utils"
import { LayoutDashboard, Search, GitCommitHorizontal, ShieldAlert, FilePlus2, Inbox, Sun, Moon, Monitor, ChevronsRight } from "lucide-react"

type View = "overview" | "search" | "timeline" | "warrantless" | "request" | "queue"
const TITLES: Record<View, string> = { overview: "개요", search: "감사 검색", timeline: "세션 타임라인", warrantless: "무영장 세션", request: "영장 발급", queue: "승인 큐" }
// 발급 화면은 시간 창 · 노드 필터와 무관하다
const ISSUE_VIEWS: View[] = ["request", "queue"]

type Theme = "system" | "light" | "dark"
// 테마 선택은 이 브라우저에만 남는다. 저장소가 막혀 있으면 OS 설정을 따른다.
function useTheme(): [Theme, (t: Theme) => void] {
  const [theme, setTheme] = useState<Theme>(() => { try { return (localStorage.getItem("sw-theme") as Theme) || "system" } catch { return "system" } })
  useEffect(() => {
    const root = document.documentElement
    if (theme === "system") root.removeAttribute("data-theme"); else root.setAttribute("data-theme", theme)
    try { localStorage.setItem("sw-theme", theme) } catch { /* 저장 못 해도 화면은 바뀐다 */ }
  }, [theme])
  return [theme, setTheme]
}

export default function App() {
  const [view, setView] = useState<View>("overview")
  const [filters, setF] = useState<Filters>(DEFAULT_FILTERS)
  const [selected, setSelected] = useState<string | null>(null)
  const [warrant, setWarrant] = useState<string | null>("W-4821-3F")
  const [wlSel, setWlSel] = useState<number | null>(null)
  // 콘솔 자체 신청 · 승인 — 목 상태. 사용자 전환으로 신청자 · 승인자를 바꿔 본다
  const [me, setMe] = useState(105)
  const [requests, setRequests] = useState<WarrantRequest[]>(seedRequests)
  const [reqSel, setReqSel] = useState<string | null>(null)
  const pendingN = requests.filter((r) => r.status === "pending").length
  const submitRequest = (r: WarrantRequest) => { setRequests((rs) => [...rs, r]); setReqSel(r.id); setView("queue") }
  const decide = (id: string, patch: Partial<WarrantRequest>) => setRequests((rs) => rs.map((r) => (r.id === id ? { ...r, ...patch, decidedBy: me, decided: NOW } : r)))
  const approve = (id: string) => { const r = requests.find((x) => x.id === id); if (!r) return; issueWarrant(r, me); decide(id, { status: "approved" }) }
  const reject = (id: string, reason: string) => decide(id, { status: "rejected", rejectReason: reason })
  const openWarrant = (id: string) => { setWarrant(id); jumpTo(NOW); setView("timeline") }
  const [theme, setTheme] = useTheme()
  // 화면을 바꾸면 맨 위에서 시작한다. 이전 화면의 스크롤 위치를 끌고 오지 않는다.
  useEffect(() => { window.scrollTo({ top: 0 }) }, [view])
  const setFilters = (p: Partial<Filters>) => setF((f) => ({ ...f, ...p }))
  // 시간 창 이동 — 좌우 스크롤 · 끌기 · 내비게이터가 모두 여기로 온다
  const panBy = (dt: number) => setF((f) => ({ ...f, until: clampUntil(f.until + dt, f.range) }))
  const jumpTo = (t: number) => setF((f) => ({ ...f, until: clampUntil(t, f.range) }))
  const setRange = (r: Range) => setF((f) => ({ ...f, range: r, until: clampUntil(f.until, r) }))
  const panned = filters.until < NOW
  const issuing = ISSUE_VIEWS.includes(view)

  const all = baseEvents(filters)
  const blockedN = all.filter(blocked).length
  const wlN = warrantlessIn(filters).length

  // 노드 패널은 노드 필터와 무관하게 전체를 보여준다 — 다른 노드로 옮겨 가는 입구다.
  const fleet = { ...filters, node: "all" }
  const fleetEv = baseEvents(fleet), fleetGaps = gapsIn(fleet), fleetWl = warrantlessIn(fleet)

  /** 다른 화면에서 행을 누르면 검색 화면으로 가서 그 레코드를 연다. 검색 필터는 초기화한다. */
  const openEvent = (id: string, subject: Filters["subject"] = "all") => {
    // 창 밖의 레코드면 그 시각이 보이도록 창을 옮긴다
    const e = events.find((x) => x.id === id)
    const until = e && (e.ts < since(filters) || e.ts > filters.until) ? clampUntil(e.ts + (filters.range * MIN) / 2, filters.range) : filters.until
    setSelected(id); setFilters({ verdict: "all", hook: "all", subject, q: "", until }); setView("search")
  }
  const openSession = (cg: number) => { setWlSel(cg); setView("warrantless") }

  const NavItem = ({ v, icon: Icon, count, hot }: { v: View; icon: React.ComponentType<{ className?: string }>; count?: string; hot?: boolean }) => (
    <Button variant="ghost" size="sm" aria-current={view === v ? "page" : undefined} onClick={() => setView(v)}
      className={cn("relative h-8 shrink-0 justify-start gap-2.5 px-2.5 font-normal text-ink-2 hover:bg-muted hover:text-foreground dark:hover:bg-muted md:w-full",
        view === v && "bg-card font-semibold text-foreground shadow-xs ring-1 ring-border hover:bg-card dark:hover:bg-card md:before:absolute md:before:inset-y-1.5 md:before:-left-3 md:before:w-[3px] md:before:rounded-r md:before:bg-foreground")}>
      <Icon className="size-4" />{TITLES[v]}
      {count && <span className={cn("ml-auto rounded px-1.5 font-mono text-[11px] leading-[18px]", hot ? "bg-deny-wash font-semibold text-deny" : "text-muted-foreground")}>{count}</span>}
    </Button>
  )
  const Section = ({ children }: { children: React.ReactNode }) => <div className="hidden px-2.5 pb-1 pt-3 font-mono text-[10.5px] uppercase tracking-[.08em] text-muted-foreground md:block">{children}</div>

  return (
    <TooltipProvider>
      <div className="grid min-h-screen grid-cols-1 md:grid-cols-[232px_1fr]">
        <aside className="flex flex-col gap-2 border-b bg-sidebar p-3 md:sticky md:gap-4 md:top-0 md:h-screen md:overflow-y-auto md:border-b-0 md:border-r">
          <div className="flex items-center gap-2.5 px-2.5 pt-1.5">
            <span className="grid size-7 shrink-0 place-items-center rounded-md bg-foreground font-mono text-[11px] font-semibold tracking-tight text-background" aria-hidden>SW</span>
            <div className="leading-tight">
              <div className="text-[15px] font-bold tracking-tight">Session Warrant</div>
              <div className="font-mono text-[10.5px] uppercase tracking-[.08em] text-muted-foreground">감사 콘솔</div>
            </div>
          </div>

          <nav className="-mx-3 flex gap-1 overflow-x-auto px-3 [scrollbar-width:none] md:mx-0 md:flex-col md:gap-0.5 md:overflow-visible md:px-0" aria-label="화면">
            <Section>감사</Section>
            <NavItem v="overview" icon={LayoutDashboard} />
            <NavItem v="search" icon={Search} count={fmtN(blockedN)} />
            <NavItem v="timeline" icon={GitCommitHorizontal} />
            <NavItem v="warrantless" icon={ShieldAlert} count={wlN ? String(wlN) : undefined} hot />
            <Section>발급</Section>
            <NavItem v="request" icon={FilePlus2} />
            <NavItem v="queue" icon={Inbox} count={pendingN ? String(pendingN) : undefined} />
          </nav>

          <div className="hidden flex-col gap-0.5 md:flex" aria-label="노드">
            <Section>노드 · {Object.keys(nodes).length}대</Section>
            {Object.entries(nodes).map(([n, info]) => {
              const on = filters.node === n
              const wl = fleetWl.filter((s) => s.node === n).length
              const gap = fleetGaps.some((g) => g.node === n)
              const blk = fleetEv.filter((e) => e.node === n && blocked(e)).length
              return (
                <button key={n} onClick={() => setFilters({ node: on ? "all" : n })} aria-pressed={on}
                  title={`커널 ${info.kernel} · lsm=${info.lsm}`}
                  className={cn("relative grid grid-cols-[1fr_auto] items-center gap-x-2 rounded-md px-2.5 py-1.5 text-left hover:bg-muted focus-visible:outline-2 focus-visible:outline-ring",
                    on && "bg-card shadow-xs ring-1 ring-foreground hover:bg-card")}>
                  <span className="truncate font-mono text-[12px] font-medium">{n}</span>
                  <span className="flex items-center gap-1">
                    {gap && <span className="hatch inline-block size-3 rounded-sm border border-gap/40" title="감사 유실 구간 있음" />}
                    {wl > 0 && <span className="rounded bg-deny-wash px-1 font-mono text-[10.5px] font-semibold text-deny" title="무영장 세션">{wl}</span>}
                  </span>
                  <span className="col-span-2 font-mono text-[10.5px] text-muted-foreground">{info.mode} · 차단 {fmtN(blk)}</span>
                </button>
              )
            })}
          </div>

          <div className="mt-auto hidden flex-col gap-3 px-2.5 pb-1 md:flex">
            <ToggleGroup type="single" variant="outline" size="sm" value={theme} onValueChange={(v) => { if (v) setTheme(v as Theme) }} aria-label="테마" className="w-full">
              <ToggleGroupItem value="system" aria-label="시스템 설정" className="flex-1"><Monitor className="size-3.5" /></ToggleGroupItem>
              <ToggleGroupItem value="light" aria-label="라이트" className="flex-1"><Sun className="size-3.5" /></ToggleGroupItem>
              <ToggleGroupItem value="dark" aria-label="다크" className="flex-1"><Moon className="size-3.5" /></ToggleGroupItem>
            </ToggleGroup>
          </div>
        </aside>

        <div className="flex min-w-0 flex-col">
          <header className="z-10 md:sticky md:top-0 flex flex-wrap items-center gap-x-6 gap-y-3 border-b bg-background/85 px-4 py-3 backdrop-blur-md md:px-7">
            <h1 className="text-[19px] font-bold leading-tight tracking-tight">{TITLES[view]}</h1>
            <div className="flex flex-wrap items-center gap-3 lg:ml-auto">
              {!issuing && <>
              <Label>기간
                <ToggleGroup type="single" variant="outline" size="sm" value={String(filters.range)} onValueChange={(v) => { if (v) setRange(Number(v) as Range) }}>
                  <ToggleGroupItem value="60" className="px-2.5 font-mono text-xs">1h</ToggleGroupItem>
                  <ToggleGroupItem value="180" className="px-2.5 font-mono text-xs">3h</ToggleGroupItem>
                  <ToggleGroupItem value="360" className="px-2.5 font-mono text-xs">6h</ToggleGroupItem>
                </ToggleGroup>
              </Label>
              <Label>노드
                <Select value={filters.node} onValueChange={(v) => setFilters({ node: v })}>
                  <SelectTrigger size="sm" className="w-[200px] font-mono text-xs"><SelectValue /></SelectTrigger>
                  <SelectContent><SelectItem value="all">전체 노드</SelectItem>{Object.keys(nodes).map((n) => <SelectItem key={n} value={n} className="font-mono text-xs">{n} · {nodes[n].mode}</SelectItem>)}</SelectContent>
                </Select>
              </Label>
              </>}
              <Label>사용자
                <Select value={String(me)} onValueChange={(v) => setMe(Number(v))}>
                  <SelectTrigger size="sm" className="w-[130px] text-xs"><SelectValue /></SelectTrigger>
                  <SelectContent>{Object.values(subjects).map((p) => <SelectItem key={p.id} value={String(p.id)} className="text-xs">{p.name}{p.approver ? " · 승인자" : ""}</SelectItem>)}</SelectContent>
                </Select>
              </Label>
              <Badge variant="outline" className="h-5 border-dashed px-1.5 font-mono text-[10.5px] font-normal text-muted-foreground">목 데이터</Badge>
            </div>
            {!issuing && <div className="flex basis-full flex-wrap items-start gap-x-3 gap-y-1.5">
              <TimeNavigator filters={filters} onPan={panBy} onJump={jumpTo} />
              {/* 폰에서는 창 시각이 내비게이터 위 한 줄로 올라간다 */}
              <div className="order-first flex w-full items-center justify-between gap-1 sm:order-none sm:w-auto sm:shrink-0 sm:flex-col sm:items-end sm:pt-0.5">
                <span className="font-mono text-xs"><span className="text-muted-foreground">{fmtMD(since(filters))}</span> {fmtHM(since(filters))}–{fmtHM(filters.until)}</span>
                {panned && <Button size="sm" variant="outline" className="h-6 gap-1 px-2 text-[11px]" onClick={() => jumpTo(NOW)}>지금으로<ChevronsRight className="size-3.5" /></Button>}
              </div>
            </div>}
          </header>
          <main className="flex flex-col gap-5 px-4 pb-12 pt-5 md:px-7">
            {view === "request" && <WarrantRequestView key={me} me={me} nextId={nextWarrantId} onSubmit={submitRequest} />}
            {view === "queue" && <ApprovalQueue requests={requests} me={me} selected={reqSel} setSelected={setReqSel} onApprove={approve} onReject={reject} onOpenWarrant={openWarrant} />}
            {view === "overview" && <Overview filters={filters} onOpenEvent={openEvent} onOpenSession={openSession} onPan={panBy} />}
            {view === "search" && <AuditSearch filters={filters} setFilters={setFilters} selected={selected} onSelect={setSelected} />}
            {view === "timeline" && <WarrantTimeline filters={filters} warrant={warrant} setWarrant={setWarrant} onOpenEvent={openEvent} />}
            {view === "warrantless" && <Warrantless filters={filters} selected={wlSel} setSelected={setWlSel} onOpenEvent={(id) => openEvent(id, "none")} />}
          </main>
        </div>
      </div>
    </TooltipProvider>
  )
}
