// 노드 한 대에 기록이 확 몰리면 어떻게 되는가.
//
// 노드 수를 늘리는 spike.js 와 반대다 — 스트림은 하나로 두고 **보내는 속도**만 올린다.
// 현실로 치면 「평소 조용하던 서버에서 갑자기 로그인이 쏟아지는」 상황이다.
//
//   평소 → 확 몰림 → 평소   세 구간을 돌고, 구간마다 ack 지연을 따로 잰다.
//   마지막 구간이 핵심이다 — **몰린 뒤 지연이 원래대로 돌아오는가.**
//
//   k6 run event-spike.js
//   k6 run -e SPIKE_RATE=50000 event-spike.js          더 세게
//   k6 run -e WARRANT_IDS=1,2,3 event-spike.js         대시보드에서 볼 거면
//   k6 run -e PKI= -e ADDR=localhost:9091 event-spike.js
//
// 영장 세션 기록과 그 세션의 커널 판정을 섞어 보낸다. 세션 기록이 더 비싸다 —
// 서버가 audit_event 와 warranted_session 두 테이블에 쓴다.
//   -e SESSION_EVERY=0  세션만 보낸다. 대신 대시보드의 판정 추이는 빈다(origin=LSM 만 센다)
import grpc from 'k6/net/grpc';
import encoding from 'k6/encoding';
import { setTimeout } from 'k6/timers';
import { Counter, Gauge, Trend } from 'k6/metrics';
import exec from 'k6/execution';

const tick = (ms) => new Promise((r) => setTimeout(r, ms));

const ADDR = __ENV.ADDR || 'localhost:9090';
const PKI = __ENV.PKI === undefined ? '../../.cache/pki' : __ENV.PKI;
const HOST = __ENV.HOST || 'k6-node-01';
const BATCH = Number(__ENV.BATCH || 100);
const EPOCH = __ENV.EPOCH || String(Date.now() * 1000 + Math.floor(Math.random() * 1000));

// 구간마다 초당 몇 건을 목표로 하는가. 스파이크는 평소의 수십 배다.
const BASE_RATE = Number(__ENV.BASE_RATE || 200);
const SPIKE_RATE = Number(__ENV.SPIKE_RATE || 20000);
const PHASES = [
  { key: 'base', label: '일반', secs: Number(__ENV.BASE_SECS || 20), rate: BASE_RATE },
  { key: 'spike', label: '부하', secs: Number(__ENV.SPIKE_SECS || 20), rate: SPIKE_RATE },
  { key: 'recover', label: '회복', secs: Number(__ENV.RECOVER_SECS || 30), rate: BASE_RATE },
];

// warrantd 의 큐와 같은 상한. 넘치면 실제 노드는 오래된 것부터 버리고 유실 구간을 남긴다.
const MAX_BACKLOG = Number(__ENV.MAX_BACKLOG || 10000);
const SLOT = 100; // 속도를 맞추는 단위(ms)

const WARRANT_IDS = (__ENV.WARRANT_IDS || '').split(',').map(Number).filter((n) => n > 0);
const WARRANT_BASE = Number(__ENV.WARRANT_BASE || 9500);
const ACCOUNTS = ['ec2-user', 'ops', 'deploy', 'root'];
// 세션 하나에 커널 판정 몇 건이 딸리는가. 실측(lima-sw)은 세션당 762건이었다. 0 이면 세션만.
const SESSION_EVERY = Number(__ENV.SESSION_EVERY || 200);
const DENY_PCT = Number(__ENV.DENY_PCT || 3);
// 한 세션이 내는 훅의 비율. exec 가 가장 잦다 — 실측에서 전체의 47% 였다.
const HOOK_PICK = [
  ['HOOK_BPRM_CHECK_SECURITY', 55], ['HOOK_FILE_OPEN', 25], ['HOOK_INODE_UNLINK', 7],
  ['HOOK_INODE_RENAME', 5], ['HOOK_SOCKET_CONNECT', 7], ['HOOK_TASK_KILL', 1],
].flatMap(([h, w]) => Array(w).fill(h));

const sessions = new Counter('spike_session_events');
const sent = new Counter('spike_events_sent');
const acked = new Counter('spike_events_acked');
const dropped = new Counter('spike_events_dropped');
const backlogHigh = new Gauge('spike_backlog_high');
const ackLatency = {
  base: new Trend('spike_ack_base', true),
  spike: new Trend('spike_ack_spike', true),
  recover: new Trend('spike_ack_recover', true),
};

const TLS = PKI
  ? { cert: open(`${PKI}/nodes/${HOST}.pem`), key: open(`${PKI}/nodes/${HOST}.key`), cacerts: [open(`${PKI}/ca.pem`)] }
  : null;

const client = new grpc.Client();
client.load(['../../proto'], 'agent.proto');

const total = PHASES.reduce((a, p) => a + p.secs, 0);
console.log(`event-spike: ${ADDR} · ${PKI ? `mTLS(${HOST})` : '평문'} · `
  + PHASES.map((p) => `${p.label} ${p.rate}/s×${p.secs}초`).join(' → ')
  + ` · 영장 ${WARRANT_IDS.length ? WARRANT_IDS.join(',') : `#${WARRANT_BASE}~ (서버에 없는 번호)`}`);

export const options = {
  scenarios: {
    node: { executor: 'per-vu-iterations', vus: 1, iterations: 1, maxDuration: `${total + 120}s` },
  },
};

function base(seq) {
  return {
    nodeSeq: String(seq),
    cpuSeq: String(seq),
    bootTsNs: String(seq * 1000),
    wallTsUnixNs: String(Date.now() * 1000000),
  };
}

// 커널 판정 한 건. 영장이 붙은 세션에서만 나온다 — warrant_id 가 0 이면 화면이 판정 추이에서 뺀다.
function kernelEvent(seq, ses) {
  const hook = HOOK_PICK[seq % HOOK_PICK.length];
  // 훅 고르기와 같은 수를 쓰면 차단이 한 훅에만 몰린다 (HOOK_PICK 길이가 100).
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
      e.fileWrite = { file, fFlags: 577 };
      break;
    case 'HOOK_INODE_UNLINK':
      e.inodeMutate = { op: 'OP_UNLINK', dir: file, name: `tmp${seq % 200}` };
      break;
    case 'HOOK_INODE_RENAME':
      e.inodeMutate = { op: 'OP_RENAME', dir: file, name: `a${seq % 200}`, newDir: file, newName: `b${seq % 200}` };
      break;
    case 'HOOK_SOCKET_CONNECT':
      e.connect = { family: 'FAMILY_INET', addr: encoding.b64encode('\x01\x01\x01\x01'), port: 443, sockType: 1 };
      break;
    case 'HOOK_TASK_KILL':
      e.selfProtection = { file };
      break;
  }
  return e;
}

// 영장 세션 한 건. 접속마다 cgroup 이 새 값이어야 화면이 한 줄로 뭉치지 않는다.
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

// 커널 판정이 달릴 세션. 영장 번호는 서버에 있는 것을 줘야 화면이 매번 전체를 다시 읽지 않는다.
function newSession(n, cgroup) {
  return {
    warrantId: WARRANT_IDS.length ? WARRANT_IDS[n % WARRANT_IDS.length] : WARRANT_BASE + (n % 60),
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
  try {
    client.connect(ADDR, { timeout: '10s', ...(TLS ? { tls: TLS } : { plaintext: true }) });
  } catch (e) {
    exec.test.abort(`${ADDR} 에 ${PKI ? 'mTLS' : '평문'}으로 못 붙었다: ${e.message}\n`
      + `  서버가 mtls 프로필이면 -e PKI=<인증서 디렉터리>, 아니면 -e PKI= 로 맞춘다.`);
    return;
  }

  const stream = new grpc.Stream(client, 'seswar.warrant.v1.AuditIngestService/Stream');
  const pending = []; // [{seq, t, n, phase}] — ack 를 기다리는 배치
  let backlog = 0; // ack 안 된 이벤트 수. warrantd 의 큐 길이에 해당한다
  let high = 0;
  let failed = '';

  stream.on('data', (ack) => {
    if (ack.seqEpoch !== EPOCH) return;
    const through = Number(ack.ackedThroughNodeSeq);
    const now = Date.now();
    while (pending.length && pending[0].seq <= through) {
      const b = pending.shift();
      ackLatency[b.phase].add(now - b.t);
      acked.add(b.n);
      backlog -= b.n;
    }
  });
  stream.on('error', (e) => { failed = `${e.code} ${e.message}`; });

  let seq = 0;
  let n = 0;
  let cgroup = 90000000;
  let first = true;
  let sinceSession = Infinity; // 첫 배치에서 세션을 하나 연다
  let session = newSession(++n, ++cgroup);

  for (const ph of PHASES) {
    const until = Date.now() + ph.secs * 1000;
    while (Date.now() < until && !failed) {
      const slotEnd = Date.now() + SLOT;
      let left = Math.max(1, Math.round((ph.rate * SLOT) / 1000));

      while (left > 0 && !failed) {
        // 큐가 차면 실제 노드는 오래된 것부터 버린다. 여기서는 보내지 않고 센다.
        if (backlog >= MAX_BACKLOG) {
          dropped.add(left);
          break;
        }
        const count = Math.min(BATCH, left);
        const events = [];
        for (let i = 0; i < count; i++) {
          // 세션 하나가 열리고 그 아래로 커널 판정이 쏟아지는 모양.
          // SESSION_EVERY 가 0 이면 세션만 보낸다.
          if (SESSION_EVERY === 0 || sinceSession >= SESSION_EVERY) {
            session = newSession(++n, ++cgroup);
            events.push(warrantedSession(++seq, session));
            sessions.add(1);
            sinceSession = 0;
          } else {
            events.push(kernelEvent(++seq, session));
            sinceSession++;
          }
        }
        const batch = { events, lastNodeSeq: String(seq), seqEpoch: EPOCH };
        if (first) {
          batch.node = {
            hostname: HOST,
            kernelVersion: '6.8.0-k6',
            bpfLsmEnabled: true,
            bootedAtUnixNs: String(Date.now() * 1000000),
            agentVersion: 'k6-event-spike',
          };
          first = false;
        }
        pending.push({ seq, t: Date.now(), n: count, phase: ph.key });
        stream.write(batch);
        sent.add(count);
        backlog += count;
        if (backlog > high) {
          high = backlog;
        }
        left -= count;
      }

      // 남은 시간만큼 양보한다. 이때 ack 콜백이 돈다 — sleep() 을 쓰면 안 돌아간다.
      await tick(Math.max(1, slotEnd - Date.now()));
    }
  }

  // 밀린 것이 빠지는 데 걸리는 시간. 여기까지 못 빠지면 회복하지 못한 것이다.
  const drainFrom = Date.now();
  for (let i = 0; i < 600 && pending.length && !failed; i++) {
    await tick(50);
  }
  const drainMs = Date.now() - drainFrom;

  stream.end();
  await tick(200);
  client.close();

  backlogHigh.add(high);
  console.log(`밀린 최대 ${high.toLocaleString()}건 · 마지막까지 빠지는 데 ${drainMs}ms`
    + (failed ? ` · 스트림 오류: ${failed}` : ''));
}

export function handleSummary(data) {
  const m = (name) => (data.metrics[name] || {}).values || {};
  const fmt = (v) => (v === undefined ? '-' : `${v.toFixed(1)}ms`);
  const s = m('spike_events_sent').count || 0;
  const a = m('spike_events_acked').count || 0;
  const d = m('spike_events_dropped').count || 0;

  const rows = PHASES.map((p) => {
    const v = m(`spike_ack_${p.key}`);
    return `  ${p.label.padEnd(4)} 목표 ${String(p.rate).padStart(6)}/s   `
      + `ack 평균 ${fmt(v.avg).padStart(9)} · 중위 ${fmt(v.med).padStart(9)} · p95 ${fmt(v['p(95)']).padStart(9)} · 최대 ${fmt(v.max).padStart(9)}`;
  });

  // 회복 구간의 **평균**은 밀린 것을 빼내는 앞부분에 끌려간다 — 중위로 본다.
  // 평균이 중위보다 한참 크면 「결국 돌아왔지만 한동안 밀렸다」는 뜻이다.
  const base = m('spike_ack_base').med;
  const rec = m('spike_ack_recover');
  const verdict = base === undefined || rec.med === undefined ? '  회복 판정 불가 — 구간 데이터가 없다'
    : rec.med <= base * 1.5
      ? `  ✓ 회복됐다 — 평소 중위 ${fmt(base)} → 회복 중위 ${fmt(rec.med)}`
        + (rec.avg > rec.med * 2 ? ` (평균 ${fmt(rec.avg)} — 앞부분은 밀린 것을 빼내느라 느렸다)` : '')
      : `  ✗ 안 돌아왔다 — 평소 중위 ${fmt(base)} → 회복 중위 ${fmt(rec.med)} (${(rec.med / base).toFixed(1)}배)`;

  const text = ['', ...rows, '',
    `  보낸 ${s.toLocaleString()}건 (세션 ${(m('spike_session_events').count || 0).toLocaleString()}건) · `
      + `ack ${a.toLocaleString()}건 · 큐가 차서 못 보낸 ${d.toLocaleString()}건`,
    `  밀린 최대 ${(m('spike_backlog_high').value || 0).toLocaleString()}건 (상한 ${MAX_BACKLOG.toLocaleString()})`,
    verdict, '',
  ].join('\n');

  const out = { stdout: text };
  if (__ENV.OUT) {
    out[`${__ENV.OUT}/event-spike-summary.json`] = JSON.stringify(data, null, 2);
  }
  return out;
}
