# web/

대시보드. TypeScript · React 19 · Vite. **Grafana 로 대체 가능** — 초기에는 Grafana 가 합리적이다.

## 화면

| 화면 | 내용 |
|---|---|
| 영장 발급 | 사유·대상·기한 입력 → 승인 요청 |
| 승인 큐 | 승인자 뷰. 본인 요청 자기승인 금지 |
| 세션 타임라인 | 영장 하나의 lineage (요청→발급→연장→만료/취소) |
| 감사 검색 | 차단 전건 · 허용은 exec/connect 만 (§13, §14) |

## 규칙

- 화면에 "모든 명령"이라고 쓰지 않는다. `cd` 한 번이면 반증된다(셸 빌트인은 exec 이 없다).
  → "실행된 모든 프로세스를 사람에게 귀속시켜 기록합니다".
- argv 는 흐리게 표시하고 근거는 **바이너리 inode** 로 보여준다. argv 는 `exec -a` 로 위조 가능하고
  BPF 스택 제약으로 잘린다 (§14).
- 감사 유실 구간은 **명시적으로 표시**한다. "빈 구간"을 숨기면 감사가 아니다.
- 빌드 산출물 `web/dist` 는 커밋하지 않는다.

## 프로젝트 구조 (2026-09-06)

Vite 7 · React 19 · TypeScript · Tailwind 4 · shadcn/ui (new-york, `radix-ui`). 차트는 shadcn `chart`(recharts 3).

```sh
npm install
npm run dev            # http://localhost:5173
npm run build          # tsc -b && vite build → dist/
npm run build:single   # 공유용 단일 HTML → dist-single/index.html
npx shadcn@latest add <component>   # 컴포넌트 추가. components.json 이 경로를 안다
```

| 경로 | 내용 |
|---|---|
| `src/data.ts` | 시드 고정 목 데이터 — 지난 24시간. 필드명은 `docs/session-warrant-ebpf-fields.html` §03·§11 을 따른다. 실서비스에서는 중앙 감사 API 가 이 자리를 대신한다 |
| `src/lib/filters.ts` | 기간·노드·판정·훅·주체·검색어 필터와 시간 창 끝(`until`). 모든 화면이 같은 함수로 이벤트를 고른다 |
| `src/lib/pan.ts` | 좌우 스크롤(가로 스와이프 · Shift+휠) · 끌기를 5분 단위 창 이동으로 바꾸는 훅. 세로 스크롤은 건드리지 않는다 |
| `src/views/` | 개요 · 감사 검색 · 세션 타임라인(영장 계보) · 무영장 세션 · 영장 발급(신청) · 승인 큐 |
| `src/components/` | `event-table`(유실 구간을 제자리에 빗금 행으로) · `event-detail`(§03 공통 메타 전체) · `timeline-chart` · `kpi`(개요 타일 · 스파크라인 · 판정 범례) · `time-navigator`(24시간 기록 띠 · 보는 창) · `pills` |
| `src/components/ui/` | shadcn 생성물. 손대지 말고 CLI 로 갱신 |
| `src/index.css` | 흑백 원장 톤 · IBM Plex. 색은 판정 3색(차트·칩)과 critical/warning 강조에만 쓴다. 판정 3색은 색각이상 검증 통과 |
| `dashboard/` | 같은 화면의 바닐라 HTML/CSS/JS 판. 빌드 없이 열린다. 의존성 없는 참고용 |

위 「규칙」 네 줄이 코드에 어떻게 반영됐는지: 허용 쓰기는 개별 행 없이 5분 집계 한 건, argv 는 흐리게·inode 가 앞, 유실 구간은 빗금 행으로 표 안에 끼워 넣는다.
발급 · 승인 큐는 콘솔 자체 신청 · 승인(Slack 연동 없음)의 목 화면이다. 요청은 화면 상태로만 살고(새로고침하면 시드로 돌아감), 승인하면 `issueWarrant` 가 영장 목록에 넣어 다른 화면에도 보인다. 헤더의 「사용자」로 신청자 · 승인자를 바꿔 본인 승인 금지를 확인한다. 정책 lint 는 `src/lib/lint.ts` 하나를 신청 화면과 승인 큐가 같이 쓴다.
