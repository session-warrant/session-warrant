// 대시보드가 쓰는 읽기 API 가 쌓인 감사 테이블에서 얼마나 버티는가.
//
// 화면이 실제로 부르는 순서를 그대로 흉내 낸다 (session-warrant-web src/live.ts):
//   받은 순번 뒤 차분 조회 · 구간 막대 집계 · 노드 목록 · 무영장 세션.
//
// 쓰기(ingest.js)와 같이 돌려야 의미가 있다 — 적재가 advisory lock 을 쥐는 동안
// 읽기가 느려지는지가 이 둘을 겹쳐 보는 이유다. run.sh --both 가 그렇게 돌린다.
import http from 'k6/http';
import encoding from 'k6/encoding';
import { check } from 'k6';
import { Trend } from 'k6/metrics';

const API = __ENV.API || 'http://localhost:8080';
const VUS = Number(__ENV.VUS || 5);
const DURATION = Number(__ENV.DURATION || 30);
const NODE = __ENV.NODE || ''; // 노드 이름으로 좁히면 화면의 「노드별」과 같은 질의가 된다

// dev 프로필은 Basic, oidc 프로필은 Bearer. run.sh 가 둘 중 하나를 넣어 준다.
const auth = __ENV.TOKEN
  ? `Bearer ${__ENV.TOKEN}`
  : __ENV.BASIC
    ? `Basic ${encoding.b64encode(__ENV.BASIC)}`
    : '';

const latency = {
  events: new Trend('read_events', true),
  events_after: new Trend('read_events_after', true),
  summary: new Trend('read_summary', true),
  nodes: new Trend('read_nodes', true),
  unwarranted: new Trend('read_unwarranted', true),
};

export const options = {
  scenarios: {
    dashboard: {
      executor: 'constant-vus',
      vus: VUS,
      duration: `${DURATION}s`,
    },
  },
};

function get(name, path) {
  const r = http.get(`${API}${path}`, {
    headers: auth ? { Authorization: auth } : {},
    tags: { endpoint: name },
  });
  latency[name].add(r.timings.duration);
  check(r, { [`${name} 200`]: (res) => res.status === 200 });
  return r;
}

export default function () {
  const node = NODE ? `&node=${NODE}` : '';

  // 처음 화면: 최근 24시간, 발생 시각 최신 순.
  const ev = get('events', `/api/audit/events?limit=1000${node}`);

  // 이어 받기: 화면은 받은 순번의 최댓값 뒤를 묶는다. 위 응답은 발생 시각 순이라
  // 마지막 행이 가장 큰 순번이 아니다 — 최댓값을 직접 고른다.
  let after = 0;
  try {
    for (const row of ev.json()) {
      if (row.seq > after) {
        after = row.seq;
      }
    }
  } catch (e) { /* 401 · 빈 응답. check 가 이미 실패로 잡았다 */ }
  if (after) {
    get('events_after', `/api/audit/events?after=${after}&limit=1000${node}`);
  }

  // 구간 막대. 화면은 막대 72개 안팎이 되게 bucketSeconds 를 고른다 — 1시간 ÷ 72 ≈ 50초.
  const to = new Date();
  const from = new Date(to.getTime() - 3600 * 1000);
  get('summary', `/api/audit/summary?from=${from.toISOString()}&to=${to.toISOString()}&bucketSeconds=50${node}`);

  get('nodes', '/api/nodes');
  get('unwarranted', '/api/audit/unwarranted');
}

export function handleSummary(data) {
  const out = {};
  out[`${__ENV.OUT || '.'}/read-summary.json`] = JSON.stringify(data, null, 2);
  return out;
}
