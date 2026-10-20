import { useEffect, useRef } from "react"
import { PAN_STEP } from "@/lib/filters"

interface PanOpts {
  /** 지금 이 요소에서 1px 이 몇 ms 인가 — 이벤트 때마다 다시 묻는다 (폭이 바뀌어도 맞게) */
  msPerPx: (el: HTMLElement) => number
  /** 창 끝을 dt 만큼 옮긴다. dt 는 늘 PAN_STEP 의 배수로 온다 */
  onPan: (dt: number) => void
  /** 끌기 방향. 내용을 끄는 차트는 -1(오른쪽으로 끌면 과거), 창을 끄는 내비게이터는 +1 */
  dragSign: -1 | 1
  /** 누른 순간 할 일 — 내비게이터는 창 밖을 누르면 거기로 뛴다 */
  onDown?: (e: PointerEvent, el: HTMLElement) => void
}

/**
 * 좌우 스크롤(트랙패드 가로 스와이프 · Shift+휠)과 끌기로 시간 창을 옮긴다.
 * 세로 스크롤은 건드리지 않는다 — 페이지는 평소처럼 위아래로 내려간다.
 */
export function usePan<T extends HTMLElement>(opts: PanOpts) {
  const ref = useRef<T>(null)
  const o = useRef(opts)
  o.current = opts

  useEffect(() => {
    const el = ref.current
    if (!el) return
    let acc = 0
    // 작은 움직임을 모았다가 5분이 차면 한 칸씩 넘긴다
    const push = (dt: number) => {
      acc += dt
      const steps = Math.trunc(acc / PAN_STEP)
      if (steps) { acc -= steps * PAN_STEP; o.current.onPan(steps * PAN_STEP) }
    }

    const onWheel = (e: WheelEvent) => {
      const dx = Math.abs(e.deltaX) > Math.abs(e.deltaY) ? e.deltaX : e.shiftKey ? e.deltaY : 0
      if (!dx) return
      e.preventDefault() // 브라우저 뒤로 가기 스와이프를 막는다
      const px = e.deltaMode === 1 ? dx * 16 : dx
      push(px * o.current.msPerPx(el))
    }

    let lastX: number | null = null
    const onDownEv = (e: PointerEvent) => {
      if (e.button !== 0) return
      o.current.onDown?.(e, el)
      lastX = e.clientX; acc = 0
      el.setPointerCapture(e.pointerId)
      el.dataset.dragging = ""
    }
    const onMove = (e: PointerEvent) => {
      if (lastX === null) return
      const dx = e.clientX - lastX
      lastX = e.clientX
      push(o.current.dragSign * dx * o.current.msPerPx(el))
    }
    const onUp = (e: PointerEvent) => {
      if (lastX === null) return
      lastX = null
      if (el.hasPointerCapture(e.pointerId)) el.releasePointerCapture(e.pointerId)
      delete el.dataset.dragging
    }

    el.addEventListener("wheel", onWheel, { passive: false })
    el.addEventListener("pointerdown", onDownEv)
    el.addEventListener("pointermove", onMove)
    el.addEventListener("pointerup", onUp)
    el.addEventListener("pointercancel", onUp)
    return () => {
      el.removeEventListener("wheel", onWheel)
      el.removeEventListener("pointerdown", onDownEv)
      el.removeEventListener("pointermove", onMove)
      el.removeEventListener("pointerup", onUp)
      el.removeEventListener("pointercancel", onUp)
    }
  }, [])

  return ref
}
