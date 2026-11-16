// 중앙 서버의 감사 수집 경로가 초당 몇 건을 받아 적을 수 있는가.
//
//   노드 N대(VU N개) → gRPC AuditIngestService/Stream → 서버 → audit_event
//
// 재는 건 두 가지다: 처리량(events/s)과 ack 지연. 노드를 늘려도 처리량이 안 늘면
// 적재가 직렬화된 것이다 — 서버는 받은 순번(received_seq)을 advisory lock 으로 직렬화한다.
//
//   k6 run ingest.js                                    노드 1대 · 30초 · 평문
//   k6 run -e NODES=4 -e DURATION=60 ingest.js
//   k6 run -e PKI=../../.cache/pki ingest.js            mtls 프로필 서버
//   k6 run -e ADDR=localhost:9091 ingest.js             t3.micro 컨테이너
//   k6 run -e SESSION_EVERY=5 ingest.js                 세션 이벤트를 더 촘촘히
//
// 처리량을 **검산하려면** run.sh 로 돌린다. 적재가 멱등이라 보낸 것이 전건 중복으로
// 걸러져도 k6 쪽은 빨랐다고 보고하는데, run.sh 는 DB 행수 증가분과 맞춰 본다.
import grpc from 'k6/net/grpc';
import { setTimeout } from 'k6/timers';
import { Counter, Trend } from 'k6/metrics';
import exec from 'k6/execution';

// k6 의 sleep() 은 VU 를 통째로 멈춘다 — 이벤트 루프까지 멈춰서 스트림의 ack 콜백이
// 반복이 끝날 때까지 안 들어온다(2026-11-16 실측: ack 지연이 전건 40초로 찍혔다).
// await 로 양보해야 ack 가 제때 들어온다.
const tick = (ms) => new Promise((r) => setTimeout(r, ms));

const ADDR = __ENV.ADDR || 'localhost:9090';
const NODES = Number(__ENV.NODES || 1);
const DURATION = Number(__ENV.DURATION || 30); // 부하 시간(초)
const BATCH = Number(__ENV.BATCH || 100); // 배치당 이벤트 수. warrantd 기본 묶음과 같게
const WINDOW = Number(__ENV.WINDOW || 4); // ack 안 된 배치를 몇 개까지 띄워 두는가
const PREFIX = __ENV.PREFIX || 'k6-node-';
const PKI = __ENV.PKI || ''; // 비어 있으면 평문. mtls 프로필이면 인증서 디렉터리

// 세션 이벤트를 몇 배치마다 한 건 섞는가. 0 이면 안 섞는다.
// 실제 비율을 흉내 낸다 — 로그인 한 번에 커널 판정이 수백 건 난다.
const SESSION_EVERY = Number(__ENV.SESSION_EVERY || 20);
const UNWARRANTED_PCT = Number(__ENV.UNWARRANTED_PCT || 20); // 세션 중 무영장 비율
// 서버에 없는 번호다. 화면에 #9500 처럼 보인다 (dev/dummy-audit.sh 의 9001~9060 과 안 겹친다).
const WARRANT_BASE = Number(__ENV.WARRANT_BASE || 9500);

// 실행마다 달라야 한다. 적재 키가 (node_id, seq_epoch, node_seq) 라 같은 epoch 를
// 다시 쓰면 서버가 전건 중복으로 걸러 「빠르게 아무것도 안 하는」 측정이 된다.
// run.sh 는 제 값을 넣어 주고, 단독 실행이면 여기서 뽑는다.
const EPOCH = __ENV.EPOCH || String(Date.now() * 1000 + Math.floor(Math.random() * 1000));

const sent = new Counter('ingest_events_sent');
const acked = new Counter('ingest_events_acked');
const batches = new Counter('ingest_batches_sent');
const sessions = new Counter('ingest_session_events');
const ackLatency = new Trend('ingest_ack_latency', true);

// 인증서는 init 단계에서만 읽을 수 있다. 노드마다 제 인증서가 필요하다 —
// 서버는 NodeHello 의 hostname 이 인증서 CN 과 다르면 거부한다.
const certs = [];
if (PKI) {
  for (let i = 1; i <= NODES; i++) {
    const host = PREFIX + String(i).padStart(2, '0');
    certs.push({
      cert: open(`${PKI}/nodes/${host}.pem`),
      key: open(`${PKI}/nodes/${host}.key`),
      cacerts: [open(`${PKI}/ca.pem`)],
    });
  }
}

const client = new grpc.Client();
client.load(['../../proto'], 'agent.proto');

export const options = {
  scenarios: {
    nodes: {
      executor: 'per-vu-iterations',
      vus: NODES,
      iterations: 1, // 한 반복이 스트림 하나다. 노드는 스트림을 며칠씩 열어 둔다
      maxDuration: `${DURATION + 120}s`,
    },
  },
};

const ACCOUNTS = ['ec2-user', 'ops', 'deploy', 'root'];
const REASONS = ['REASON_NO_WARRANT', 'REASON_NO_KEY', 'REASON_KEY_MISMATCH', 'REASON_AGENT_UNREACHED'];

// 공통 칸. 커널 판정과 세션 기록이 같은 스트림에 섞여 온다.
function base(seq, wall) {
  return {
    nodeSeq: String(seq),
    cpuSeq: String(seq),
    bootTsNs: String(seq * 1000),
    wallTsUnixNs: String(wall),
    origin: 'ORIGIN_LSM',
  };
}

// 커널 판정 한 건. exec 는 빈도가 가장 높고 허용도 기록되는 훅이라 수집 경로의 최악 조건이다.
function execEvent(seq, host, cgroup) {
  return {
    ...base(seq, Date.now() * 1000000),
    cpu: seq % 8,
    hook: 'HOOK_BPRM_CHECK_SECURITY',
    verdict: 'VERDICT_ALLOW',
    mode: 'MODE_OBSERVE',
    warrantId: '0',
    tagSource: 'TAG_CGROUP',
    process: { pid: 1000 + (seq % 5000), tgid: 1000 + (seq % 5000), comm: 'k6load', cgroupId: String(cgroup) },
    exec: { filename: '/usr/bin/true', argv: `true ${host} ${seq}`, iMode: 33261 },
  };
}

// 영장 세션 한 건. warrantd binder 가 보내는 모양과 같다 (cmd/warrantd/binder.go).
// 서버는 warrant_id 가 0 이면 거부한다.
function warrantedSession(seq, host, cgroup, n) {
  return {
    ...base(seq, Date.now() * 1000000),
    cpu: 0,
    hook: 'HOOK_AGENT',
    verdict: 'VERDICT_ALLOW',
    mode: 'MODE_OBSERVE',
    origin: 'ORIGIN_AGENT',
    tagSource: 'TAG_CGROUP',
    warrantId: String(WARRANT_BASE + (n % 60)),
    subjectId: 1 + (n % 7),
    policyId: 1 + (n % 3),
    warrantedSession: {
      loginAccount: ACCOUNTS[n % ACCOUNTS.length],
      sourceAddress: `10.0.${n % 256}.${(n * 7) % 256}`,
      cgroupId: String(cgroup),
      sessionId: String(100 + (n % 900)), // XDG_SESSION_ID 는 재사용된다. cgroup id 는 아니다
      sshKeyFingerprint: `SHA256:k6load${String(n % 40).padStart(4, '0')}`,
    },
  };
}

// 무영장 세션 한 건. 사유가 없으면 서버가 거부한다 — 사유별로 돌려 쓴다.
function unwarrantedSession(seq, host, cgroup, n) {
  const reason = REASONS[n % REASONS.length];
  return {
    ...base(seq, Date.now() * 1000000),
    cpu: 0,
    hook: 'HOOK_AGENT',
    verdict: 'VERDICT_ALLOW',
    origin: 'ORIGIN_AGENT',
    tagSource: 'TAG_NONE',
    warrantId: '0',
    unwarrantedSession: {
      loginAccount: ACCOUNTS[n % ACCOUNTS.length],
      sourceAddress: `203.0.113.${n % 256}`,
      cgroupId: String(cgroup),
      sessionId: String(100 + (n % 900)),
      reason,
      // REASON_NO_KEY 는 키가 없어서 생긴 사유다. 지문을 같이 보내면 거짓이 된다.
      sshKeyFingerprint: reason === 'REASON_NO_KEY' ? '' : `SHA256:k6load${String(n % 40).padStart(4, '0')}`,
    },
  };
}

export default async function () {
  const vu = exec.vu.idInTest; // 1..NODES
  const host = PREFIX + String(vu).padStart(2, '0');
  client.connect(ADDR, PKI ? { tls: certs[vu - 1] } : { plaintext: true });

  const stream = new grpc.Stream(client, 'seswar.warrant.v1.AuditIngestService/Stream');
  const pending = []; // [{seq, t, n}] — ack 를 기다리는 배치
  let failed = '';

  stream.on('data', (ack) => {
    const ackedThrough = Number(ack.ackedThroughNodeSeq);
    const now = Date.now();
    while (pending.length && pending[0].seq <= ackedThrough) {
      const b = pending.shift();
      ackLatency.add(now - b.t);
      acked.add(b.n);
    }
  });
  stream.on('error', (e) => { failed = `${e.code} ${e.message}`; });

  let seq = 0;
  let first = true;
  let batchNo = 0;
  let sessionCount = 0;
  // cgroup id 는 재사용되지 않는다 — 세션마다 새 값이어야 화면의 「최근 접속」이 섞이지 않는다.
  let cgroup = 90000 + vu * 1000000;
  const deadline = Date.now() + DURATION * 1000;

  while (Date.now() < deadline && !failed) {
    // 창이 차면 ack 를 기다린다. 안 기다리면 보낸 쪽 큐만 쌓여 ack 지연이 의미를 잃는다.
    if (pending.length >= WINDOW) {
      await tick(2);
      continue;
    }
    const events = [];

    // 세션 하나가 열리고 그 아래로 커널 판정이 쏟아지는 모양을 흉내 낸다.
    const openSession = SESSION_EVERY > 0 && batchNo % SESSION_EVERY === 0;
    if (openSession) {
      cgroup++;
      sessionCount++;
      const n = vu * 10000 + sessionCount;
      events.push(sessionCount % 100 < UNWARRANTED_PCT
        ? unwarrantedSession(++seq, host, cgroup, n)
        : warrantedSession(++seq, host, cgroup, n));
      sessions.add(1);
    }
    while (events.length < BATCH) {
      events.push(execEvent(++seq, host, cgroup));
    }

    const batch = { events, lastNodeSeq: String(seq), seqEpoch: EPOCH };
    if (first) {
      batch.node = {
        hostname: host,
        kernelVersion: '6.8.0-k6',
        bpfLsmEnabled: true,
        bootedAtUnixNs: String(Date.now() * 1000000),
        agentVersion: 'k6-serverload',
      };
      first = false;
    }
    pending.push({ seq, t: Date.now(), n: events.length });
    stream.write(batch);
    sent.add(events.length);
    batches.add(1);
    batchNo++;
  }

  // 남은 ack 를 받는다. 못 받은 건 acked 에 안 세어져 run.sh 의 검산에서 드러난다.
  for (let i = 0; i < 600 && pending.length && !failed; i++) {
    await tick(50);
  }
  stream.end();
  await tick(200);
  client.close();

  if (failed) {
    exec.test.abort(`stream failed on ${host}: ${failed}`);
  }
}

export function handleSummary(data) {
  const m = (name) => (data.metrics[name] || {}).values || {};
  const secs = DURATION || 1;
  const s = m('ingest_events_sent').count || 0;
  const a = m('ingest_events_acked').count || 0;
  const lat = m('ingest_ack_latency');
  const fmt = (v) => (v === undefined ? '-' : `${v.toFixed(1)}ms`);

  // run.sh 가 안 거치는 단독 실행에서도 숫자가 보여야 한다. 처리량 검산은 run.sh 만 한다.
  const text = [
    '',
    `  노드 ${NODES}대 · 배치 ${m('ingest_batches_sent').count || 0}개 · ${secs}초 · epoch ${EPOCH}`,
    `  보낸 이벤트      ${s.toLocaleString()} (${Math.round(s / secs).toLocaleString()}/s)  ← 상한. DB 검산은 run.sh`,
    `  ack 된 이벤트    ${a.toLocaleString()} (${Math.round(a / secs).toLocaleString()}/s)`,
    `  세션 이벤트      ${(m('ingest_session_events').count || 0).toLocaleString()}`,
    `  ack 지연         평균 ${fmt(lat.avg)} · 중위 ${fmt(lat.med)} · p95 ${fmt(lat['p(95)'])} · 최대 ${fmt(lat.max)}`,
    '',
  ].join('\n');

  const out = { stdout: text };
  if (__ENV.OUT) {
    out[`${__ENV.OUT}/ingest-summary.json`] = JSON.stringify(data, null, 2);
  }
  return out;
}
