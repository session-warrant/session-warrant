// 재부팅 뒤 노드가 갑자기 늘어나는 시나리오
// 혹은 설정 오류로 여러 노드가 하나의 서버로 일제히 이벤트를 보내기 시작할 때 이를 잘 처리하는 지

import grpc from 'k6/net/grpc';
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter, Trend } from 'k6/metrics';
import exec from 'k6/execution';

const ADDR = __ENV.ADDR || 'localhost:9090';
const API = __ENV.API || 'http://localhost:8080';
const NODES = Number(__ENV.NODES || 1);
const PKI = __ENV.PKI === undefined ? '../../.cache/pki' : __ENV.PKI;
const HOST = __ENV.HOST || 'k6-node-01';
const EPOCH = __ENV.EPOCH || String(Date.now() * 1000 + Math.floor(Math.random() * 1000));
const DURATION = Number(__ENV.DURATION || 30);
const WINDOW = Number(__ENV.WINDOW || 4); // ack 안 된 배치를 몇 개까지 띄워 두는가
const BATCH = Number(__ENV.BATCH || 100);
const PREFIX = __ENV.PREFIX || 'k6-node-';
const WARRANT_IDS = (__ENV.WARRANT_IDS || '').split(',').map(Number).filter((n) => n > 0);
const WARRANT_BASE = Number(__ENV.WARRANT_BASE || 9500);
const ACCOUNTS = ['ec2-user', 'ops', 'deploy', 'root'];
const SESSION_EVERY = Number(__ENV.SESSION_EVERY || 20);


const warrantId = (n) => (WARRANT_IDS.length ? WARRANT_IDS[n % WARRANT_IDS.length] : WARRANT_BASE + (n % 60));


const sessions = new Counter('ingest_session_events');
const sent = new Counter('ingest_events_sent');
const batches = new Counter('ingest_batches_sent');


const client = new grpc.Client();
client.load(['../../proto'], 'agent.proto');

const STAGES = [
  { duration: '20s', target: 1 },
  { duration: '5s',  target: 20 },
  { duration: '20s', target: 20 },
  { duration: '5s',  target: 1 },
  { duration: '30s', target: 1 },
];
const MAX_VUS = Math.max(...STAGES.map((st) => st.target));

// 인증서는 init 단계에서만 읽을 수 있다. VU 마다 제 인증서가 필요하다 —
// 서버는 NodeHello 의 hostname 이 인증서 CN 과 다르면 PERMISSION_DENIED 다.
// 한 장을 돌려 쓰면 VU 1번만 통과하고 나머지는 첫 배치에서 끊긴다.
const certs = [];
if (PKI) {
  for (let i = 1; i <= MAX_VUS; i++) {
    const h = PREFIX + String(i).padStart(2, '0');
    certs.push({
      cert: open(`${PKI}/nodes/${h}.pem`),
      key: open(`${PKI}/nodes/${h}.key`),
      cacerts: [open(`${PKI}/ca.pem`)],
    });
  }
}

export const options = {
  vus: 1,
  stages: STAGES,
  thresholds: {
    http_req_failed: ['rate<0.001'],
    http_req_duration: ['p(95)<500'],
    checks: ['rate == 1'], 
  },
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


function newSession(vu, n, cgroup) {
  return {
    warrantId: warrantId(n),
    subjectId: 1 + (n % 7),
    policyId: 1 + (n % 3),
    cgroup,
    account: ACCOUNTS[n % ACCOUNTS.length],
    rhost: `10.0.${n % 256}.${(n * 7) % 256}`,
    sessionId: 100 + (n % 900),
    fingerprint: `SHA256:k6load${String(n % 40).padStart(4, '0')}`,
  };
}


function base(seq) {
  return {
    nodeSeq: String(seq),
    cpuSeq: String(seq),
    bootTsNs: String(seq * 1000),
    wallTsUnixNs: String(Date.now() * 1000000),
  };
}

function warrantedSession(seq, ses) {
  return {
    ...base(seq),
    cpu: 0,
    hook: 'HOOK_AGENT',
    verdict: 'VERDICT_ALLOW',
    mode: 'MODE_OBSERVE',
    origin: 'ORIGIN_AGENT',
    tagSource: 'TAG_CGROUP',
    warrantId: String(ses.warrantId),
    subjectId: ses.subjectId,
    policyId: ses.policyId,
    warrantedSession: {
      loginAccount: ses.account,
      sourceAddress: ses.rhost,
      cgroupId: String(ses.cgroup),
      sessionId: String(ses.sessionId),
      sshKeyFingerprint: ses.fingerprint,
    },
  };
}

function kernelEvent(seq, host, ses){
  const e = {
    ...base(seq),
    cpu : seq % 8,
    hook : 'HOOK_BPRM_CHECK_SECURITY',
    verdict: 'VERDICT_ALLOW',
    mode: 'MODE_OBSERVE',
    origin: 'ORIGIN_LSM',
    tagSource: 'TAG_CGROUP',
    warrantId: String(ses.warrantId),
    subjectId: ses.subjectId,
    policyId: ses.policyId,
    process: {
      pid: 1000 + (seq % 5000), tgid: 1000 + (seq % 5000),
      comm: ['bash', 'tail', 'cp', 'curl', 'rm'][seq % 5], 
      cgroupId: String(ses.cgroup),
    },
  };

  const file = { dev: 64769, ino: 20000 + (seq % 9000), path: `/etc/app/conf${seq % 50}`};

  e.exec = { file, iMode: 33261, filename: `/usr/bin/${e.process.comm}`, argv: `${e.process.comm} ${seq}` };

  return e;
}


export default async function() {
  const vu = exec.vu.idInTest;
  const host = PREFIX + String(vu).padStart(2, '0');

  const health = http.get(`${API}/actuator/health`);
  check(health, {
    "health was 200": (res) => res.status == 200,
    "health UP": (res) => res.body.includes('"status":"UP"'),
  });
  
  let connected = true;
  try{
    client.connect(ADDR, {timeout: '10s', ...(PKI ? { tls: certs[vu - 1]} : {plaintext : true}) });
  }catch(e){
    connected = false;
    console.error("client 연결 실패");
  }

  check(null, { 'gRPC 연결' : () => connected});
  if(!connected) {
    exec.test.abort('연결 실패');
    return;
  }

  const stream = new grpc.Stream(client, 'seswar.warrant.v1.AuditIngestService/Stream');

  let acked = 0;
  stream.on('data', (ack) => {
    if(ack.seqEpoch === EPOCH ) acked = Number(ack.ackedThroughNodeSeq);
  });

  stream.on('end', function(){
    client.close();
    console.log('All done');
  });

  stream.on('error', function(e){
    console.log('Error: '+JSON.stringify(e));
  })
  

  let seq = 0;
  let first = true;
  let batchNo = 0;
  let sessionCount = 0;
  let cgroup = 90000 + vu * 1000000;
  let session = newSession(vu, vu * 10000, ++cgroup);
  const deadline = Date.now() + DURATION * 1000;

  while(Date.now() < deadline){
    const events = [];
    if(SESSION_EVERY > 0 && batchNo % SESSION_EVERY === 0){
      sessionCount++;
      const n = vu * 10000 + sessionCount;
      events.push(warrantedSession(++seq, session));
      sessions.add(1);
    }

    while (events.length < BATCH){
      events.push(kernelEvent(++seq, host, session));
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

    stream.write(batch);
    sent.add(events.length);
    batches.add(1);
    batchNo++;
  }


  stream.end();
  await tick(200);
  client.close();

}