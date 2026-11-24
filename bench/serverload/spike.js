// 시나리오 : 서버가 죽은뒤 부활했을 때, 여러 노드가 각자의 큐에 쌓은 로그를 일제히 전송
// 이때 로그 저장을 안정적으로 처리하는 지 테스트
//
// 노드 20대가 각자 쌓아 둔 6,000건을 같은 순간에 붙자마자 쏟아낸다(warrantd 큐 상한: 10,000건).
// warrantd 처럼 ack 를 기다리지 않고 배치를 연달아 보낸다. 배치당 이벤트 : 500건.
//
//   k6 run spike.js        mtls 서버 :9090 (make certs NODES=20 먼저)
//
// 통과 조건: 모든 노드가 스트림 오류 없이 마지막 기록까지 ack 를 받는다. spike_drain = 첫 전송 → 마지막 ack.
// ack 는 서버가 커밋한 뒤에 온다. DB 행수로 재확인하려면 make clean-rows 가 노드별 건수를 찍는다.
// 서버 쪽 비용을 잴 거면 서버를 bootRun 이 아니라 java -jar 로 띄운다(bootRun 은 C1 만 쓴다).
import grpc from 'k6/net/grpc';
import { setTimeout } from 'k6/timers';
import { check } from 'k6';
import { Trend } from 'k6/metrics';
import exec from 'k6/execution';

const ADDR = 'localhost:9090';
const PKI = '../../.cache/pki';
const NODES = 20;
const EVENTS = 6000;  // 노드당 쌓인 기록. warrantd 큐 상한(main.go NewAuditQueue)은 10,000
const BATCH = 500;    // warrantd maxBatch
const ACK_WAIT_MS = 100_000; // 마지막 ack 를 기다리는 한도. maxDuration(2m)보다 짧아야 실패가 검사로 남는다
const EPOCH = String(Date.now() * 1000 + Math.floor(Math.random() * 1000));

const host = (i) => `k6-node-${String(i).padStart(2, '0')}`;
const tick = (ms) => new Promise((r) => setTimeout(r, ms));

const TLS = Array.from({ length: NODES }, (_, i) => ({
  cert: open(`${PKI}/nodes/${host(i + 1)}.pem`),
  key: open(`${PKI}/nodes/${host(i + 1)}.key`),
  cacerts: [open(`${PKI}/ca.pem`)],
}));

const client = new grpc.Client();
client.load(['../../proto'], 'agent.proto');

const drain = new Trend('spike_drain', true); // 첫 배치 전송 → 마지막 ack

export const options = {
  scenarios: { 
    flush: { 
      executor: 'per-vu-iterations', 
      vus: NODES, 
      iterations: 1, 
      maxDuration: '2m' 
    } 
  },
  thresholds: { checks: ['rate==1'] },
};

function event(seq, now) {
  return {
    nodeSeq: String(seq),
    cpuSeq: String(seq),
    hook: 'HOOK_BPRM_CHECK_SECURITY',
    verdict: 'VERDICT_ALLOW',
    mode: 'MODE_OBSERVE',
    origin: 'ORIGIN_LSM',
    tagSource: 'TAG_CGROUP',
    warrantId: '1',
    bootTsNs: String(seq * 1000),
    wallTsUnixNs: now,
    process: { pid: 1, tgid: 1, comm: 'k6spike', cgroupId: '1' },
    exec: { filename: '/usr/bin/true', argv: 'true', iMode: 33261 },
  };
}

export default async function () {
  const n = exec.vu.idInTest; // 1..NODES
  const name = host(n);
  client.connect(ADDR, { timeout: '10s', tls: TLS[n - 1] });

  const stream = new grpc.Stream(client, 'seswar.warrant.v1.AuditIngestService/Stream');
  let acked = 0;
  let failed = '';
  stream.on('data', (ack) => {
    if (ack.seqEpoch === EPOCH) acked = Number(ack.ackedThroughNodeSeq);
  });
  stream.on('error', (e) => { failed = `${e.code} ${e.message}`; });

  // 큐에 쌓여 있던 것을 한꺼번에 — 배치 사이에 쉬지 않는다.
  const now = String(Date.now() * 1000000);
  const start = Date.now();
  for (let seq = 0, first = true; seq < EVENTS; first = false) {
    const events = [];
    for (let i = 0; i < BATCH && seq < EVENTS; i++) events.push(event(++seq, now));
    const batch = { events, lastNodeSeq: String(seq), seqEpoch: EPOCH };
    if (first) { // the server ties the stream to a node by the first batch's NodeHello
      batch.node = { hostname: name, kernelVersion: '6.8.0-k6', bpfLsmEnabled: true, agentVersion: 'k6-spike' };
    }
    stream.write(batch);
  }

  while (acked < EVENTS && !failed && Date.now() - start < ACK_WAIT_MS) await tick(50);
  if (acked === EVENTS) drain.add(Date.now() - start, { node: name });

  stream.end();
  await tick(200);
  client.close();

  if (failed) console.error(`${name} 스트림 오류: ${failed}`);
  console.log(`${name}: ack ${acked}/${EVENTS} · ${Date.now() - start}ms`);
  check(null, {
    '스트림 유지': () => !failed,
    [`ack ${EVENTS}건 전부`]: () => acked === EVENTS,
  });
}
