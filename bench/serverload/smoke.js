import grpc from 'k6/net/grpc';
import http from 'k6/http';
import { setTimeout } from 'k6/timers';
import { check } from 'k6';
import exec from 'k6/execution';

const ADDR = __ENV.ADDR || 'localhost:9090';
const API = __ENV.API || 'http://localhost:8080';
const PKI = __ENV.PKI === undefined ? '../../.cache/pki' : __ENV.PKI;
const HOST = __ENV.HOST || 'k6-node-01';
const BATCHES = Number(__ENV.BATCHES || 3);
const BATCH = Number(__ENV.BATCH || 10);
const EPOCH = __ENV.EPOCH || String(Date.now() * 1000 + Math.floor(Math.random() * 1000));

const tick = (ms) => new Promise((r) => setTimeout(r, ms));

const TLS = PKI
  ? { cert: open(`${PKI}/nodes/${HOST}.pem`), key: open(`${PKI}/nodes/${HOST}.key`), cacerts: [open(`${PKI}/ca.pem`)] }
  : null;

const client = new grpc.Client();
client.load(['../../proto'], 'agent.proto');

console.log(`smoke: ${ADDR} · ${PKI ? `mTLS(${PKI})` : '평문'} · ${HOST} · ${BATCHES}배치 × ${BATCH}건 · epoch ${EPOCH}`);

export const options = {
  scenarios: { smoke: { executor: 'shared-iterations', vus: 1, iterations: 1, maxDuration: '60s' } },
  thresholds: { checks: ['rate==1'] },
};

function event(seq) {
  return {
    nodeSeq: String(seq),
    cpu: 0,
    cpuSeq: String(seq),
    hook: 'HOOK_BPRM_CHECK_SECURITY',
    verdict: 'VERDICT_ALLOW',
    mode: 'MODE_OBSERVE',
    origin: 'ORIGIN_LSM',
    tagSource: 'TAG_CGROUP',
    warrantId: '1',
    bootTsNs: String(seq * 1000),
    wallTsUnixNs: String(Date.now() * 1000000),
    process: { pid: 1, tgid: 1, comm: 'k6smoke', cgroupId: '1' },
    exec: { filename: '/usr/bin/true', argv: `true ${seq}`, iMode: 33261 },
  };
}

export default async function () {
  const health = http.get(`${API}/actuator/health`);
  check(health, { 'health 200': (r) => r.status === 200, 'health UP': (r) => r.body.includes('"status":"UP"') });

  let connected = true;
  try {
    client.connect(ADDR, { timeout: '10s', ...(TLS ? { tls: TLS } : { plaintext: true }) });
  } catch (e) {
    connected = false;
    console.error(`${ADDR} 에 ${PKI ? 'mTLS' : '평문'}으로 못 붙었다: ${e.message}`);
    console.error(`  서버가 mtls 프로필이면 -e PKI=<인증서 디렉터리>, 아니면 -e PKI= (평문) 로 맞춘다.`);
  }
  check(null, { 'gRPC 연결': () => connected });
  if (!connected) {
    exec.test.abort('연결 실패');
    return;
  }

  const stream = new grpc.Stream(client, 'seswar.warrant.v1.AuditIngestService/Stream');
  let acked = 0;
  let failed = '';
  stream.on('data', (ack) => {
    if (ack.seqEpoch === EPOCH) acked = Number(ack.ackedThroughNodeSeq);
  });
  stream.on('error', (e) => { failed = `${e.code} ${e.message}`; });

  let seq = 0;
  for (let b = 0; b < BATCHES && !failed; b++) {
    const events = [];
    for (let i = 0; i < BATCH; i++) events.push(event(++seq));
    const batch = { events, lastNodeSeq: String(seq), seqEpoch: EPOCH };
    if (b === 0) {
      batch.node = { hostname: HOST, kernelVersion: '6.8.0-k6', bpfLsmEnabled: true, agentVersion: 'k6-smoke' };
    }
    stream.write(batch);
    await tick(100);
  }

  for (let i = 0; i < 100 && acked < seq && !failed; i++) await tick(100);

  stream.end();
  await tick(200);
  client.close();

  if (failed) console.error(`스트림 오류: ${failed}`);
  check(null, {
    '스트림 유지': () => !failed,
    'ack 수신': () => acked > 0,
    [`ack 가 보낸 ${seq}번까지`]: () => acked === seq,
  });
}
