// 중앙 서버의 감사 수집 경로가 초당 몇 건을 받아 적을 수 있는가.
//
//   노드 N대(VU N개) → gRPC AuditIngestService/Stream → 서버 → audit_event
//
// 재는 건 두 가지다: 처리량(events/s)과 ack 지연. 노드를 늘려도 처리량이 안 늘면
// 적재가 직렬화된 것이다 — 서버는 받은 순번(received_seq)을 advisory lock 으로 직렬화한다.
//
// 혼자 돌리지 말고 run.sh 로 돌린다. 적재가 멱등이라 epoch 를 새로 안 뽑으면
// 「빠르게 아무것도 안 하는」 측정이 되는데, run.sh 가 그걸 DB 건수로 검산한다.
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
const EPOCH = __ENV.EPOCH; // run.sh 가 실행마다 새로 뽑는다. 없으면 멱등에 걸려 적재가 안 된다
const PKI = __ENV.PKI || ''; // 비어 있으면 평문. mtls 프로필이면 인증서 디렉터리

const sent = new Counter('ingest_events_sent');
const acked = new Counter('ingest_events_acked');
const batches = new Counter('ingest_batches_sent');
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

// 한 이벤트. exec 는 빈도가 가장 높고 허용도 기록되는 훅이라 수집 경로의 최악 조건이다.
function event(seq, host) {
  return {
    nodeSeq: String(seq),
    cpu: seq % 8,
    cpuSeq: String(seq),
    hook: 'HOOK_BPRM_CHECK_SECURITY',
    verdict: 'VERDICT_ALLOW',
    mode: 'MODE_OBSERVE',
    bootTsNs: String(seq * 1000),
    wallTsUnixNs: String(Date.now() * 1000000),
    warrantId: '0',
    subjectId: 0,
    policyId: 0,
    tagSource: 'TAG_CGROUP',
    origin: 'ORIGIN_LSM',
    process: { pid: 1000 + (seq % 5000), tgid: 1000 + (seq % 5000), comm: 'k6load', cgroupId: String(90000 + exec.vu.idInTest) },
    exec: { filename: `/usr/bin/true`, argv: `true ${host} ${seq}`, iMode: 33261 },
  };
}

export default async function () {
  const vu = exec.vu.idInTest; // 1..NODES
  const host = PREFIX + String(vu).padStart(2, '0');
  client.connect(ADDR, PKI ? { tls: certs[vu - 1] } : { plaintext: true });

  const stream = new grpc.Stream(client, 'seswar.warrant.v1.AuditIngestService/Stream');
  const pending = []; // [{seq, t, n}] — ack 를 기다리는 배치
  let ackedThrough = 0;
  let failed = '';

  stream.on('data', (ack) => {
    ackedThrough = Number(ack.ackedThroughNodeSeq);
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
  const deadline = Date.now() + DURATION * 1000;

  while (Date.now() < deadline && !failed) {
    // 창이 차면 ack 를 기다린다. 안 기다리면 보낸 쪽 큐만 쌓여 ack 지연이 의미를 잃는다.
    if (pending.length >= WINDOW) {
      await tick(2);
      continue;
    }
    const events = [];
    for (let i = 0; i < BATCH; i++) {
      events.push(event(++seq, host));
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
    pending.push({ seq, t: Date.now(), n: BATCH });
    stream.write(batch);
    sent.add(BATCH);
    batches.add(1);
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
  const out = {};
  out[`${__ENV.OUT || '.'}/ingest-summary.json`] = JSON.stringify(data, null, 2);
  return out;
}
