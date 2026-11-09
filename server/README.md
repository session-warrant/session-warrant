# warrant-server

Session Warrant 의 컨트롤 플레인. 영장 발급 · 승인 · 서명 · push · 취소 · 감사 조회를 담당한다.

**현재 상태:** 감사 수집 경로와 **영장 신청 → 다른 사람의 승인 → 서명 · push → 회수** 가 돈다(계보 포함).
연장 · 정책 lint · 승인자 자격(팀 · 상급자)은 아직 골격(시그니처와 의사코드 주석)이다.
설계 원본은 `docs/session-warrant-plan.html`(§ 번호) 과 `docs/session-warrant-tech-stack.html` 이다.

## 이 서버가 지는 책임과 지지 않는 책임

| 하는 일 | 하지 않는 일 |
|---|---|
| 영장 발급 · 승인 워크플로 · 서명(Ed25519) | 집행 판정 — 커널이 한다. 판정 시점에 여기로 올라오는 왕복은 없다 |
| 만료 시각 · 취소 플래그를 노드에 push | 만료 감시 타이머 — 훅이 매 판정마다 시각을 직접 비교한다 |
| 정책을 표현 형태로 보관 · lint | 경로 → inode 컴파일 — warrantd가 노드에서 한다 |
| 감사 이벤트 수집 · 조회 · 리포트 | 세션 녹화 · 터미널 입력 수집 |

중앙이 끊겨도 이미 발급된 영장의 만료와 강제는 노드에서 정확히 계속된다(§17).
**이 서버는 느슨하게 실패해야 한다.** 여기가 죽었다고 로그인이 막히면 안 된다.

## 패키지 배치

도메인별로 나눈다. 한 패키지 안에 그 도메인의 엔티티 · 저장소 · 서비스 · gRPC · REST 가 같이 있다.

```
io.seswar.warrant
├── warrant/      영장 — 엔티티 · 계보 · 상태 · 모드, 발급 · 회수 · 연장, 서명 굳히기(WarrantSealer), proto 변환, REST
│   └── push/     영장 전달 — 노드 구독 gRPC(서버 스트리밍), 열린 스트림 보관(NodeStreamRegistry), push
├── identity/     로그인 · 신원 — 주체(사람 + SSH 키 지문), REST, SecurityConfig(OIDC · dev 프로필)
├── approval/     승인 — 신청 · 승인 큐 (골격)
├── policy/       정책 — 정책 · 실행/쓰기/네트워크 규칙 · lint, REST
├── node/         노드 — 등록 · 하트비트 (NodeRegistry), REST
├── audit/        감사 — 감사 이벤트 · 무영장 세션 · 유실 구간, 수집 gRPC(클라이언트 스트리밍) · 변환 · 멱등 저장, 무영장 탐지, 조회 REST
├── signing/      서명 키 — Ed25519 키 관리 · 서명기, 공개키 REST. protobuf 바이트에 서명한다
├── common/       REST 오류 응답
└── config/       시계 · gRPC · 가상 스레드
```

방향: `warrant` → `identity` · `policy` · `signing`, `audit` → `warrant`(모드 enum) · `node`. `warrant` 와 `warrant.push` 는 서로 부른다(REST 가 커밋 뒤 push). 그 밖의 반대 방향 참조를 만들지 말 것 —
예전에 `Warrant` 가 `audit` 의 모드 변환기를 빌려 쓰던 것을 `WarrantMode.Converter` 로 옮겼다.
JPQL 의 `select new …` 는 클래스 전체 이름이 문자열에 들어간다 — 패키지를 옮기면 컴파일러가 못 잡고 기동 때 깨진다.

## 신청 · 승인 — 콘솔 자체 경로

영장 신청과 승인은 **콘솔(웹)에서 한다.** 외부 메신저 연동은 두지 않는다 (2026-10-16 결정).
신청 · 승인 · 반려는 동작한다(아래 「영장 발급」). 연장 요청과 `requestLineageId` 확인은 아직 골격이다.

| 메서드 · 경로 | 누가 | 하는 일 |
|---|---|---|
| `POST /api/warrants` | REQUESTER | 발급 신청. lint ERROR 면 큐에 올리지도 않는다 |
| `POST /api/warrants/{id}/extensions` | 영장 주체 | 연장 요청. warrantd 의 T-5분 자동 요청(gRPC `RequestExtension`)과 같은 큐로 간다 |
| `GET /api/approvals?kind=` | APPROVER | 승인 큐 — 발급 대기 + 열린 연장 요청 |
| `POST /api/approvals/{warrantId}/approve` | APPROVER | 발급 대기면 발급 · 서명 · push, 연장 요청이면 새 revision push |
| `POST /api/approvals/{warrantId}/reject` | APPROVER | 반려. 사유 필수 |

- **자기 승인 금지는 서버가 집행한다.** 승인자는 본문이 아니라 OIDC 로그인 주체에서 온다.
  요청자 == 승인자면 `ApprovalService` 가 거부하고, 연장 요청은 영장 주체 본인이 승인할 수 없다.
  콘솔의 비활성 버튼은 표시일 뿐이다.
- **승인은 멱등이다.** 본문의 `requestLineageId` 가 지금 열린 요청과 다르면 409. 이중 클릭이나
  두 승인자의 동시 클릭이 중복 발급이 되지 않는다.
- **연장 요청은 계보 한 줄(`EXTENSION_REQUESTED`)이다.** 별도 테이블을 두지 않는다 — 영장당
  열린 요청은 하나뿐이고, 상태가 계보에서 파생된다는 원칙과 맞는다. 발급 반려는 `REJECTED`.
- **CSRF 보호를 끄지 않는다.** 콘솔은 세션 쿠키로 붙으므로, 끄면 승인자가 연 다른 탭이 승인을 대신 보낼 수 있다.
- **서버는 알림을 보내지 않는다.** "승인 대기 N분 초과" · 유예 진입 · break-glass · 자기보호 훅 히트 경보는
  Grafana 경보 규칙이 PostgreSQL(계보 · 감사 이벤트)을 직접 읽어 건다. 화면을 Grafana 로 대체한 것과 같은 선이다.
- **대가:** 승인자에게 푸시가 가지 않으므로 승인 지연이 늘 수 있다. 짧은 기본 기간(§03)이 굴러가려면
  연장이 싸야 한다 — 그래서 read-only 영장의 정책 자동 승인(`warrant.extension.auto-approve`)을 유지한다.

## 영장 발급 — 신청 · 승인

**신청자와 승인자는 다른 사람이어야 한다.** 둘 다 로그인에서 정해진다 — 요청 본문의 이름은 믿지 않는다.

```
POST /api/warrants (신청자 로그인)          WarrantIssuanceService.request — REQUESTED 로 저장, 계보 REQUESTED(신청자 · 기간)
                                            서명도 push 도 없다. 노드 활성 집합에도 안 들어간다
POST /api/approvals/{id}/approve (다른 사람)  ApprovalService.approve — 본인이면 403, REQUESTED 가 아니면 409
                                            기간은 지금부터 → WarrantSealer(proto · 목록 정렬 · Ed25519) → 계보 ISSUED(승인자)
                                            (커밋 뒤) WarrantPushService.push → 대상 호스트의 열린 스트림
POST /api/approvals/{id}/reject {reason}    REJECTED, 계보 REJECTED(승인자 · 사유). 사유 없으면 400
DELETE /api/warrants/{id}                   ISSUED 만. revoked=true · revision+1 → 다시 서명 → push, 계보 REVOKED(회수한 사람)

warrantd Subscribe → WarrantPushGrpcService 스트림 등록 → 그 호스트의 ISSUED 영장 전부 → ResyncComplete
```

| 메서드 · 경로 | 하는 일 |
|---|---|
| `POST /api/subjects` · `GET` | 주체(사람) 등록. `sshKeyFingerprints` 가 비면 영장이 어떤 세션에도 안 붙는다 |
| `POST /api/policies` · `GET` | 정책 등록. 한 행 = 한 버전, 고치지 않는다 |
| `POST /api/warrants` · `GET` · `GET /{id}` | 신청 · 목록 · 단건(계보 포함). `duration` 생략 시 `warrant.default-duration`(30분), `mode` 생략 시 OBSERVE |
| `GET /api/approvals` | 승인 큐(REQUESTED). 본인 신청은 `approvable: false` |
| `POST /api/approvals/{id}/approve` · `/reject` | 승인 · 반려(`{"reason": …}` 필수) |
| `DELETE /api/warrants/{id}` | 회수 |
| `GET /api/signing-key` | 노드에 심을 공개키 PEM. 헤더 `X-Key-Id` 가 파일 이름 |
| `GET /api/nodes` · `/api/audit/unwarranted` · `/api/audit/gaps` | 대시보드용 읽기. 감사 스트림으로 들어온 노드 · 무영장 세션 · 유실 구간, 최신 순. 기간 필터 · 페이지는 아직 없다 |
| `GET /api/audit/events?since=&limit=` | 커널 판정 기록, 최신 순. 기본 최근 24시간 · 1000건(최대 5000). 훅은 proto 이름(`HOOK_FILE_OPEN`), kprobe 미러 · fork 도 그대로 준다 — 거르는 건 화면 몫 |

- **로그인은 두 가지다. 둘 다 `/api/**` 는 로그인해야 열리고(공개키만 예외), 역할 규칙 · CSRF 가 같다**(`identity/SecurityConfig`).
  - **`oidc` 프로필 — 기본으로 쓸 것.** 콘솔은 Keycloak 로그인(코드 흐름 + PKCE) → 세션, curl 은 Keycloak 액세스 토큰(Bearer).
    `docker compose -f compose.yaml --profile oidc up -d` → `../deploy/keycloak/seed-users.sh` → `SPRING_PROFILES_ACTIVE=oidc ./gradlew bootRun`.
    Keycloak 은 `127.0.0.1:8180`, realm `warrant`(`deploy/keycloak/warrant-realm.json`), 클라이언트 `warrant-server`.
    사용자는 git 밖 `server/.cache/dev-accounts.txt`(`<이메일> <비밀번호> <그룹,그룹>`)에서 넣는다. 서버는 기동할 때 Keycloak 에 묻지 않는다.
  - **역할 = Keycloak 그룹** (`groups` claim): `warrant-requesters` 신청 · `warrant-approvers` 승인 · 반려 · 회수 · `warrant-auditors` 조회만.
    자기 승인 금지는 역할과 별개로 서버가 막는다.
  - **「나」= `sub`.** 처음 보는 sub 면 주체를 만들고, 검증된 같은 이메일의 주체가 있으면 거기에 sub 를 잇는다(dev 시절 주체).
  - 로그아웃은 서버 세션과 Keycloak 세션을 둘 다 끝낸다(`GET /api/auth/config` 의 `logoutUrl`).
  - **`dev` 프로필** — Keycloak 없이 개발할 때. `application-dev.yml` 의 계정(이메일 + `{bcrypt}` 해시), 콘솔은 `POST /api/auth/login`,
    curl 은 `-u <이메일>:<비밀번호>`(Basic). dev 계정은 역할을 전부 가진다. 해시: `htpasswd -nbBC 10 "" '<비밀번호>' | cut -d: -f2`.
- 서명 키는 `warrant.signing.key-path`(기본 `.cache/signing.key`). 없으면 만들고 공개키를 `.pub` 로 옆에 둔다.
  **키를 지우면 새 키가 생긴다** — 노드는 그 뒤 push 를 전부 거부한다(`RESYNC SKIPPED`).
- 노드 신원은 mTLS 전까지 노드가 신고한 hostname 이다. 영장의 `targetHosts` 와 같은 이름으로 맞춘다.
- 계보(`warrant_lineage`)는 append-only — 저장소에 `save` 와 조회만 연다. 상태는 `warrant` 에 비정규화해 둔다.
- 같은 클래스 안에서 `@Transactional` 메서드를 부르면 프록시를 안 거쳐 트랜잭션이 없다 — 바깥 메서드에도 붙인다
  (`WarrantRevocationService.revoke(id)` 가 그래서 취소를 저장하지 못한 적이 있다).
- Jackson 3 은 요청에 없는 primitive 필드를 오류로 본다 — 요청 본문 레코드는 박싱 타입으로 받는다.
  응답에 도메인 레코드를 그대로 싣지 않는다 — `is*()` 메서드를 속성으로 읽어 부른다.

로컬에서 해 보기:

```sh
docker compose -f compose.yaml up -d --wait
SPRING_PROFILES_ACTIVE=dev ./gradlew bootRun
ME='<신청자 이메일>:<비밀번호>'; OK='<승인자 이메일>:<비밀번호>'    # application-dev.yml 의 계정 둘
curl -s localhost:8080/api/signing-key > central.pem          # 노드의 /etc/warrantd/keys/central.pem
curl -s -u "$ME" -H 'Content-Type: application/json' localhost:8080/api/subjects \
  -d '{"oidcSubject":"oidc|alice","principal":"alice@example.com","loginAccount":"ec2-user","sshKeyFingerprints":["SHA256:..."]}'
curl -s -u "$ME" -H 'Content-Type: application/json' localhost:8080/api/policies \
  -d '{"name":"ops","execRules":["/usr/bin/bash","/usr/bin/ls"],"writeRules":[{"path":"/tmp","recursive":true,"effect":"ALLOW"}]}'
curl -s -u "$ME" -H 'Content-Type: application/json' localhost:8080/api/warrants \
  -d '{"loginAccount":"ec2-user","reason":"INC-1","targetHosts":["<노드 hostname>"],"policyId":"<id>","duration":"PT20M","mode":"DRYRUN"}'
curl -s -u "$OK" -X POST localhost:8080/api/approvals/<id>/approve       # 다른 사람이 승인 → 서명 · push
curl -s -u "$OK" -X DELETE localhost:8080/api/warrants/<id>
```

## 감사 수집 — 재전송 멱등

warrantd → `AuditIngestGrpcService`(gRPC 스트림) → `AuditIngestService.ingest` → PostgreSQL.
**`AuditBatch` 하나 = `ingest` 호출 하나 = 트랜잭션 하나 = ack 하나.**

- **중복 수신을 전제로 한다.** warrantd 는 ack 를 못 받으면 마지막 ack 이후를 다시 보낸다. 보내는 쪽에서
  중복을 막는 대신 받는 쪽이 멱등하게 받는다.
- **멱등 키.** 감사 이벤트 · 무영장 세션은 `(node_id, seq_epoch, node_seq)`, 유실 구간은 구간 자체
  `(node_id, from_at, to_at, cause)`. 셋 다 DB UNIQUE 로 걸려 있다(V1 · V2). `seq_epoch` 가 키에 없으면
  bbolt 초기화 뒤 1 로 돌아간 `node_seq` 의 새 이벤트가 중복으로 버려진다.
- **저장 순서.** 이미 있는 키를 배치의 seq 범위로 한 번에 조회해 빼고(같은 배치 안의 중복도 뺀다),
  남은 것만 `saveAllAndFlush`. 조회와 저장 사이에 같은 키가 끼어들면 UNIQUE 가 막고 배치 전체가 롤백된다 —
  ack 가 안 나가니 재전송 때 건너뛴다.
- **flush 는 `ingest` 안에서 한다.** 커밋 때로 미루면 UNIQUE 위반이 이 메서드 밖에서 터진다.
  ack 를 보내기 전에, `ingest` 가 예외로 끝나야 한다.
- **세 테이블을 한 트랜잭션으로 묶는다.** 반쯤 저장된 배치가 남으면 그 뒤의 ack 가 거짓이 된다.
- **ack 는 `ingest` 가 정상 반환한 뒤에만.** 저장 전에 ack 하면 서버가 죽었을 때 warrantd 는 이미 지운 기록을
  다시 보낼 수 없다.
- **배치 안의 행은 전부 그 스트림의 노드 것이어야 한다.** 섞이면 거부한다 — 남의 노드 이름으로 기록된다.
- **수집 경로에서 조인하지 않는다.** `kernelSubjectId` → 주체 이름은 조회 시점에 붙인다. 수집 경로에 넣으면
  처리량이 주체 테이블 락에 묶인다.
- **경보는 보내지 않는다.** 무영장 세션 · 자기보호 히트 경보는 Grafana 가 이 테이블들을 읽어 건다.
- **적재는 Hibernate JDBC 배치**(`hibernate.jdbc.batch_size: 100`). 쿼리가 "조회 1 + INSERT" 라 예전
  `INSERT … ON CONFLICT` 한 번보다 많다. 수집량이 병목이 되면 `audit_event` 하나만 `ON CONFLICT` 로 되돌린다.

## 노드 (`node/Node`)

영장을 집행하는 호스트. warrantd 한 대가 한 노드다. 테이블은 `node`(V1).

| 필드 | 뜻 · 제약 |
|---|---|
| `clientCertFingerprint` | mTLS 클라이언트 인증서 지문. **노드 신원은 이것이다.** 감사 멱등 키 `(node_id, seq_epoch, node_seq)` 의 `node_id` 는 이 값으로 찾은 `id` 다. UNIQUE |
| `hostname` | 노드가 신고한 이름(`NodeHello.hostname`). 자기 신고라 **키로 쓰지 않는다.** 인증서의 것과 다르면 경보한다 |
| `kernelVersion` · `agentVersion` | 노드 신고값. 진단용 |
| `bpfLsmEnabled` | `/sys/kernel/security/lsm` 에 `bpf` 가 있는가. **false 면 그 노드에 ENFORCE 영장을 발급해도 강제되지 않는다** — 발급 시점에 거부하거나 최소한 승인자에게 알려야 한다. 조용히 통과시키면 "막고 있다고 믿는데 안 막히는" 최악의 상태가 된다 |
| `attachedHooks` | 지금 붙어 있는 훅(`NodeHello.attached_hooks`), `TEXT[]`. 훅을 하나씩 붙이는 동안 "이 노드는 `file_open` 을 아직 안 본다"를 알아야 빈 데이터를 "아무 일 없음"으로 오해하지 않는다 |
| `currentSeqEpoch` | 지금 감사 `seq_epoch`. warrantd 의 bbolt 가 초기화되면 바뀐다 — **바뀐 사실 자체가 조사 대상이다** |
| `lastSeenAt` | 마지막 하트비트. gRPC 스트림이 살아 있는지와는 별개로 기록한다 |
| `bootedAt` | 노드 부팅 시각. 절대시각 → `bpf_ktime_get_boot_ns` 변환의 기준이지만 **변환은 warrantd 가 한다.** 여기 값은 시계 스큐 진단용 참고 정보일 뿐이다 |

## 감사 엔티티 (`audit/`)

공통 규칙:
- **enum 칼럼은 순서(ordinal)가 아니라 proto 번호를 `SMALLINT` 로 저장한다** (`AuditEnumConverters`). Java enum 순서를
  바꿔도 과거 행의 뜻이 바뀌지 않고, Grafana 가 DB 를 직접 읽어도 proto 문서 하나로 해석된다.
  `Origin` 은 proto 의 0 이 UNSPECIFIED 라 LSM=1 부터다 — 순서로 저장하면 여기서 어긋난다.
  서버에만 있는 분류(`AuditEventType`, 각종 reason · cause)는 이름을 `TEXT` 로 저장한다.
- **훅에 따라 비는 칸은 래퍼 타입**(`Long` · `Integer`). 기본형은 NULL 을 못 담아 읽을 때 터진다.
- 만드는 방법: `AuditEvent.builder()`, `UnwarrantedSession.of(...)`, `EventGap.of(...)`. gRPC 층이 proto 에서 만든다.

### `AuditEvent` — 감사 레코드 한 건 (`audit_event`)

커널 ringbuf → warrantd → gRPC 로 도착한다. 일 단위 range 파티션(`occurred_at`)이라 DB 의 PK 는 `(id, occurred_at)` 이다.
**남는 것**(§14): 실행된 모든 프로세스, 자원에 손댄 순간. **안 남는 것**: 셸 빌트인(`cd`), 인터프리터 내부 로직,
파일 읽기, 터미널 입력.

| 필드 | 뜻 · 제약 |
|---|---|
| `nodeId` | mTLS 인증서로 찾은 노드. 노드가 신고한 hostname 이 아니다 |
| `seqEpoch` · `nodeSeq` | `(nodeId, seqEpoch, nodeSeq)` 가 재전송 멱등 키(「감사 수집」). `seqEpoch` 가 없으면 bbolt 초기화 뒤 1 로 돌아간 `nodeSeq` 의 새 이벤트가 중복으로 버려진다 |
| `warrantId` | 커널이 들고 있던 u64(proto `warrant_id`). `Warrant.warrantId` 와 조인한다. **0 이면 영장 없는 프로세스** — 그 자체가 조사 대상이다 |
| `kernelSubjectId` | 커널이 들고 있던 u32. 조회 시점에 사람 이름으로 조인한다 |
| `mode` | `WOULD_DENY` 가 OBSERVE 인지 DRYRUN 인지 가른다 |
| `tagSource` | `TASK` 면 cgroup 을 벗어난 프로세스를 2차 방어선(fork 전파)이 잡은 것이다 |
| `origin` | lsm 과 kprobe 미러가 같은 입력에 다른 verdict 를 내면 버그다(§15). warrantd 발은 `AGENT` |
| `uid` | sudo 뒤의 uid. **신원이 아니라 정황 정보다** — 신원은 `warrantId` 쪽에 있다 |
| `deviceId` · `inode` | 커널이 실제로 연 파일의 `(dev, ino)`. **신뢰의 근거는 이것이다** |
| `resolvedPath` | 해석된 경로. 리포트 가독성용 참고 정보이며 증거로 쓰지 않는다 |
| `argvTruncated` | 명령줄 인자. **1급 증거가 아니다**(§14) — BPF 스택 제약으로 잘리고 `exec -a` 한 줄이면 argv[0] 이 위조된다 |
| `destination` | `CONNECT` · `UDP_SEND` 의 목적지. AF_UNIX 면 `sun_path` |

### `UnwarrantedSession` — 영장 없이 성립한 SSH 세션 (`unwarranted_session`, §07 STEP 2)

| 필드 | 뜻 · 제약 |
|---|---|
| `seqEpoch` · `nodeSeq` | 이 세션을 실어 온 감사 이벤트의 키. `(nodeId, seqEpoch, nodeSeq)` 가 재전송 멱등 키다(V2) |
| `sshKeyFingerprint` | 공개키 지문(`SHA256:...`). 비어 있으면 `NO_KEY`. **이 값으로 사람을 역추적한다** — 공유 계정에서 사람을 가르는 유일한 값 |
| `reason` | proto `UnwarrantedSessionEvent.Reason`: `NO_WARRANT` · `NO_KEY` · `KEY_MISMATCH` · `AGENT_UNREACHED` · `CENTRAL_STALE` · `PAM_ABSENT` |
| `observedEventCount` | 이 세션이 실제로 한 일 — 연결된 감사 이벤트 수. "무영장 세션이 몇 건"보다 "무영장 세션이 무엇을 했다"가 훨씬 강한 자료다. **아직 0 으로만 들어간다** |

### `EventGap` — 유실 구간 (`audit_gap`)

**빈 구간을 숨기지 않고 명시적으로 기록한다**(§14). 감추면 조사자가 "이 시간대에는 아무 일도 없었다"로 잘못 읽는다.

| 필드 | 뜻 · 제약 |
|---|---|
| `from` · `to` | 빠진 구간. 칼럼 이름은 `from_at` · `to_at` — `from` · `to` 가 SQL 예약어라서 |
| `droppedCount` | 커널 ringbuf 가 보고한 드롭 수. **모르면 NULL** — 0 과 구분한다 |
| `cause` | proto `GapReport.Cause`: `RINGBUF_OVERFLOW` · `AGENT_DOWN` · `LOCAL_STORE_FULL` · `CPU_SEQ_SKIP` |

## 의존성에서 한 번 걸리는 지점

Spring Boot 4 는 Boot 3 과 스타터 좌표가 다르고, gRPC 는 아예 소속이 바뀌었다.

| Boot 3 에서 쓰던 것 | Boot 4 에서 | 
|---|---|
| `spring-boot-starter-web` | `spring-boot-starter-webmvc` |
| `spring-boot-starter-oauth2-client` | `spring-boot-starter-security-oauth2-client` |
| `flyway-core` 직접 | `spring-boot-starter-flyway` |
| `org.springframework.grpc:spring-grpc-spring-boot-starter` | `org.springframework.boot:spring-boot-starter-grpc-server` |
| `org.testcontainers:junit-jupiter` | `org.testcontainers:testcontainers-junit-jupiter` |

**spring-grpc 의 자체 스타터는 1.0.3 에서 멈췄다.** 1.1.x 에는 `spring-grpc-core` 만 배포되고
스타터는 Spring Boot 쪽으로 옮겨갔다. 그래서 `spring-grpc-dependencies` BOM 을 import 해도
스타터 버전이 채워지지 않고 `Could not find org.springframework.grpc:spring-grpc-spring-boot-starter:.`
로 실패한다 — 빈 버전이 그 증상이다. Boot BOM 하나에 맡기면 된다
(Boot 4.1.1 이 spring-grpc 1.1.1 · grpc-java 1.83.1 · protobuf-java 4.35.1 을 관리한다).

protobuf-gradle-plugin 은 BOM 을 읽지 못하므로 `ext.protobufVersion` · `ext.grpcVersion` 을
직접 적어 뒀다. **Boot 버전을 올릴 때 이 두 값을 같이 확인할 것** — 어긋나면
생성 코드와 런타임 라이브러리가 다른 버전이 되어 진단하기 어려운 오류가 난다.

## 구현 순서

1. `../proto/warrant.proto` 확정 — 이게 늦어지면 커널 담당과 검증 담당이 서로를 기다린다
2. `Warrant` · `Policy` 엔티티 + Flyway V1
3. 발급 → 서명 → push 경로 (`WarrantIssuanceService` → `WarrantSigner` → `WarrantPushService`) — 단순 CRUD 로 돈다(2026-11-08)
4. 감사 수집 (`AuditIngestService`) 및 무영장 세션 탐지
5. 콘솔 신청 · 승인 큐 · 연장 정책
