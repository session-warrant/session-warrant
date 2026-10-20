import type { WarrantRequest } from "@/data"

export interface Lint { level: "warn" | "crit"; text: string }

/** 정책 lint — 신청 화면과 승인 큐가 같은 결과를 본다. 조합으로만 위험한 것까지 잡는다. */
export function lintPolicy(r: Pick<WarrantRequest, "node" | "mode" | "policy" | "minutes">): Lint[] {
  const out: Lint[] = []
  const { write, exec, net } = r.policy
  const under = (root: string) => write.some((p) => p === root || p.startsWith(root + "/"))
  if (exec.includes("systemctl") && under("/etc/systemd")) out.push({ level: "crit", text: "systemctl 실행 + /etc/systemd 쓰기 = 임의 코드 실행 경로" })
  if (exec.includes("python3")) out.push({ level: "warn", text: "실행 허용에 인터프리터 python3" })
  const broad = write.filter((p) => ["/", "/etc", "/usr", "/var", "/root", "/home"].includes(p))
  if (broad.length) out.push({ level: "crit", text: `쓰기 범위가 넓음 · ${broad.join(", ")}` })
  if (net.includes("0.0.0.0/0")) out.push({ level: "crit", text: "네트워크 전면 허용 · 0.0.0.0/0" })
  if (r.mode === "enforce" && r.node.startsWith("prod-")) out.push({ level: "warn", text: `prod 노드에 enforce · ${r.node}` })
  if (r.minutes > 120 && (write.length || net.length)) out.push({ level: "warn", text: `쓰기 · 네트워크 허용에 ${r.minutes / 60}시간` })
  return out
}
