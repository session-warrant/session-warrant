// 중앙 서버의 감사 수집 경로가 초당 몇 건을 받아 적을 수 있는가.
//
//   노드 N대(VU N개) → gRPC AuditIngestService/Stream → 서버 → audit_event
//
// 재는 건 두 가지다: 처리량(events/s)과 ack 지연. 노드를 늘려도 처리량이 안 늘면
// 적재가 직렬화된 것이다 — 서버는 받은 순번(received_seq)을 advisory lock 으로 직렬화한다.
//
//   k6 run ingest.js                                    노드 1대 · 30초 · mTLS
//   k6 run -e NODES=4 -e DURATION=60 ingest.js
//   k6 run -e PKI= ingest.js                            평문 (mtls 프로필 없이 띄운 서버)
//   k6 run -e PKI= -e ADDR=localhost:9091 ingest.js     t3.micro 컨테이너(dev 프로필)
//   k6 run -e SESSION_EVERY=5 ingest.js                 세션 이벤트를 더 촘촘히
//   k6 run -e DENY_PCT=10 ingest.js                     차단 판정을 더 섞는다
//   k6 run -e WARRANT_IDS=1,2,3 ingest.js               서버에 있는 영장 번호로 (대시보드 확인용)
//

import grpc from 'k6/net/grpc';
import encoding from 'k6/encoding';
import { setTimeout } from 'k6/timers';
import { Counter, Trend } from 'k6/metrics';
import exec from 'k6/execution';

const tick = (ms) => new Promise((r) => setTimeout(r, ms));

const ADDR = __ENV.ADDR || 'localhost:9090';
const NODES = Number(__ENV.NODES || 1);
const DURATION = Number(__ENV.DURATION || 30); // 부하 시간(초)
const BATCH = Number(__ENV.BATCH || 100); // 배치당 이벤트 수. warrantd 기본 묶음과 같게
const WINDOW = Number(__ENV.WINDOW || 4); // ack 안 된 배치를 몇 개까지 띄워 두는가
const PREFIX = __ENV.PREFIX || 'k6-node-';
// 기본은 mTLS 다 — 제품의 노드 ↔ 중앙은 mTLS 이고, 평문은 로컬 개발 전용이다.
// `-e PKI=` 로 비우면 평문. 서버 프로필과 안 맞으면 아래 connect 가 그걸 짚어 준다.
const PKI = __ENV.PKI === undefined ? '../../.cache/pki' : __ENV.PKI;
// 기본 60초는 너무 길다 — 프로필이 안 맞으면 1분을 기다린 뒤에야 알게 된다.
const CONNECT_TIMEOUT = __ENV.CONNECT_TIMEOUT || '10s';

// 세션 이벤트를 몇 배치마다 한 건 섞는가. 0 이면 안 섞는다.
// 실제 비율을 흉내 낸다 — 로그인 한 번에 커널 판정이 수백 건 난다.
const SESSION_EVERY = Number(__ENV.SESSION_EVERY || 20);
const UNWARRANTED_PCT = Number(__ENV.UNWARRANTED_PCT || 20); // 세션 중 무영장 비율
// 차단 비율. 영장이 감사 모드(OBSERVE)라 차단은 WOULD_DENY 로 나간다 — 실제로 막지는 않는다.
const DENY_PCT = Number(__ENV.DENY_PCT || 3);
/**
 * 세션에 붙일 영장 번호.
 *
 * 기본은 서버에 없는 번호(9500~)라 화면에 `#9500` 으로 보인다. **대시보드를 볼 거면
 * 서버에 있는 번호를 줘야 한다** — 모르는 번호가 오면 화면이 「페이지가 열린 뒤 발급된
 * 영장인가」 하고 전체를 다시 읽는데, 그때 들고 있던 기록이 최근 한 페이지로 갈려서
 * 막대가 사라진다(2026-11-16). run.sh 가 인증을 받으면 GET /api/warrants 로 채워 준다.
 */
const WARRANT_IDS = (__ENV.WARRANT_IDS || '').split(',').map(Number).filter((n) => n > 0);
const WARRANT_BASE = Number(__ENV.WARRANT_BASE || 9500);
const warrantId = (n) => (WARRANT_IDS.length ? WARRANT_IDS[n % WARRANT_IDS.length] : WARRANT_BASE + (n % 60));

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

console.log(`ingest: ${ADDR} · ${PKI ? `mTLS(${PKI})` : '평문'} · 노드 ${NODES}대 · ${DURATION}초`
  + ` · 영장 ${WARRANT_IDS.length ? WARRANT_IDS.join(',') : `#${WARRANT_BASE}~ (서버에 없는 번호 — 대시보드가 매번 다시 읽는다)`}`);

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

// 한 세션이 내는 훅의 비율. exec 가 가장 잦고, 자기보호는 드물다.
// 화면의 「훅별」 막대가 한 칸만 차지 않게 실제 세션의 성질을 흉내 낸다.
const HOOKS = [
  ['HOOK_BPRM_CHECK_SECURITY', 55],
  ['HOOK_FILE_OPEN', 25],
  ['HOOK_INODE_UNLINK', 7],
  ['HOOK_INODE_RENAME', 5],
  ['HOOK_SOCKET_CONNECT', 7],
  ['HOOK_TASK_KILL', 1],
];
const HOOK_PICK = HOOKS.flatMap(([h, w]) => Array(w).fill(h));

// 공통 칸. 커널 판정과 세션 기록이 같은 스트림에 섞여 온다.
function base(seq) {
  return {
    nodeSeq: String(seq),
    cpuSeq: String(seq),
    bootTsNs: String(seq * 1000),
    wallTsUnixNs: String(Date.now() * 1000000),
  };
}

/**
 * 커널 판정 한 건. **영장을 거느린 세션에서만 나온다** — 태그가 없으면 lookup_warrant 가
 * 비어서 LSM 훅이 아무것도 안 남기고 빠져나가기 때문이다. warrant_id 가 0 인 커널 판정은
 * 제품에서 생기지 않는 조합이고, 대시보드도 그런 건 판정 추이에서 뺀다
 * (session-warrant-web src/lib/filters.ts — `if (!c.warranted) continue`).
 */
function kernelEvent(seq, host, ses) {
  const hook = HOOK_PICK[seq % HOOK_PICK.length];
  // 훅 고르기와 같은 수를 쓰면 안 된다 — HOOK_PICK 길이가 100 이라 차단이 exec 에만 몰린다
  // (2026-11-16: WOULD_DENY 2,602건이 전건 EXEC 였다).
  const denied = Math.random() * 100 < DENY_PCT;
  const e = {
    ...base(seq),
    cpu: seq % 8,
    hook,
    verdict: denied ? 'VERDICT_WOULD_DENY' : 'VERDICT_ALLOW',
    mode: 'MODE_OBSERVE',
    origin: 'ORIGIN_LSM',
    tagSource: 'TAG_CGROUP',
    warrantId: String(ses.warrantId),
    subjectId: ses.subjectId,
    policyId: ses.policyId,
    process: {
      pid: 1000 + (seq % 5000), tgid: 1000 + (seq % 5000),
      comm: ['bash', 'tail', 'cp', 'curl', 'rm'][seq % 5], cgroupId: String(ses.cgroup),
    },
  };
  const file = { dev: 64769, ino: 20000 + (seq % 9000), path: denied ? `/etc/app/conf${seq % 50}` : '' };
  switch (hook) {
    case 'HOOK_BPRM_CHECK_SECURITY':
      e.exec = { file, iMode: 33261, filename: `/usr/bin/${e.process.comm}`, argv: `${e.process.comm} ${seq}` };
      break;
    case 'HOOK_FILE_OPEN':
      e.fileWrite = { file, fFlags: 577 }; // O_WRONLY|O_CREAT|O_TRUNC
      break;
    case 'HOOK_INODE_UNLINK':
      e.inodeMutate = { op: 'OP_UNLINK', dir: file, name: `tmp${seq % 200}` };
      break;
    case 'HOOK_INODE_RENAME':
      e.inodeMutate = { op: 'OP_RENAME', dir: file, name: `a${seq % 200}`, newDir: file, newName: `b${seq % 200}` };
      break;
    case 'HOOK_SOCKET_CONNECT':
      // addr 은 네트워크 바이트 오더 4바이트. k6 는 bytes 를 base64 로 싣는다
      e.connect = { family: 'FAMILY_INET', addr: encoding.b64encode('\x01\x01\x01\x01'), port: 443, sockType: 1 };
      break;
    case 'HOOK_TASK_KILL':
      e.selfProtection = { file };
      break;
  }
  return e;
}

// 영장 세션 한 건. warrantd binder 가 보내는 모양과 같다 (cmd/warrantd/binder.go).
// 서버는 warrant_id 가 0 이면 거부한다.
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
      sessionId: String(ses.sessionId), // XDG_SESSION_ID 는 재사용된다. cgroup id 는 아니다
      sshKeyFingerprint: ses.fingerprint,
    },
  };
}

// 무영장 세션 한 건. **그 아래로 커널 판정은 안 나온다** — 태그가 없기 때문이다.
// 사유가 없으면 서버가 거부하므로 사유별로 돌려 쓴다.
function unwarrantedSession(seq, n) {
  const reason = REASONS[n % REASONS.length];
  return {
    ...base(seq),
    cpu: 0,
    hook: 'HOOK_AGENT',
    verdict: 'VERDICT_ALLOW',
    origin: 'ORIGIN_AGENT',
    tagSource: 'TAG_NONE',
    warrantId: '0',
    unwarrantedSession: {
      loginAccount: ACCOUNTS[n % ACCOUNTS.length],
      sourceAddress: `203.0.113.${n % 256}`,
      cgroupId: String(90000000 + n),
      sessionId: String(100 + (n % 900)),
      reason,
      // REASON_NO_KEY 는 키가 없어서 생긴 사유다. 지문을 같이 보내면 거짓이 된다.
      sshKeyFingerprint: reason === 'REASON_NO_KEY' ? '' : `SHA256:k6load${String(n % 40).padStart(4, '0')}`,
    },
  };
}

// 커널 판정이 달릴 세션 하나. 번호는 서버에 없는 것이라 화면에 #9500 처럼 보인다.
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

export default async function () {
  const vu = exec.vu.idInTest; // 1..NODES
  const host = PREFIX + String(vu).padStart(2, '0');
  try {
    client.connect(ADDR, {
      timeout: CONNECT_TIMEOUT,
      ...(PKI ? { tls: certs[vu - 1] } : { plaintext: true }),
    });
  } catch (e) {
    // 거의 언제나 서버 프로필과 안 맞는 것이다. 「server preface: EOF」는 평문으로
    // TLS 서버에 붙었을 때 서버가 핸드셰이크 전에 끊는 모양이다 (deploy/README.md).
    exec.test.abort(`${ADDR} 에 ${PKI ? 'mTLS' : '평문'}으로 못 붙었다: ${e.message}\n`
      + `  서버가 mtls 프로필이면 -e PKI=<인증서 디렉터리>, 아니면 -e PKI= (평문) 로 맞춘다.\n`
      + `  지금 뜬 서버의 모드는 make check 가 찍어 준다.`);
    return;
  }

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
  // 커널 판정이 달릴 영장 세션. 첫 배치에서 연다 — 이게 없으면 판정을 만들 수 없다.
  let session = newSession(vu, vu * 10000, ++cgroup);
  const deadline = Date.now() + DURATION * 1000;

  while (Date.now() < deadline && !failed) {
    // 창이 차면 ack 를 기다린다. 안 기다리면 보낸 쪽 큐만 쌓여 ack 지연이 의미를 잃는다.
    if (pending.length >= WINDOW) {
      await tick(2);
      continue;
    }
    const events = [];

    // 세션 하나가 열리고 그 아래로 커널 판정이 쏟아지는 모양을 흉내 낸다.
    if (SESSION_EVERY > 0 && batchNo % SESSION_EVERY === 0) {
      sessionCount++;
      const n = vu * 10000 + sessionCount;
      if (sessionCount % 100 < UNWARRANTED_PCT) {
        // 무영장 세션은 기록만 남고 커널 판정을 거느리지 않는다. 판정은 열려 있던 영장 세션이 계속 낸다.
        events.push(unwarrantedSession(++seq, n));
      } else {
        session = newSession(vu, n, ++cgroup);
        events.push(warrantedSession(++seq, session));
      }
      sessions.add(1);
    }
    while (events.length < BATCH) {
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
