# proto/

**단일 진실 원본.** `struct warrant`(커널) · `Warrant`(서버 엔티티) · BPF 맵 값이 모두 여기서 나온다.
여기가 흔들리면 커널 구조체와 서버 엔티티가 어긋나고, 그때부터 디버깅이 지옥이 된다.

## 파일 (2026-09-09 초안 — 스파이크 S0~S3 뒤에 작성)

| 파일 | 내용 |
|---|---|
| `warrant.proto` | `SignedWarrant` 봉투 · `Warrant` 본체 · `Mode` · `OnExpiry` · `Policy`(exec/write/net 규칙) |
| `audit.proto` | `AuditEvent`(공통 메타 + 훅별 oneof) · `WriteAggregate` · `GapReport` · `Hook` · `Verdict` |
| `agent.proto` | `WarrantPushService`(push 서버 스트리밍 · heartbeat · 연장 요청 · 조회) · `AuditIngestService`(양방향 스트리밍) |

`server/` 에서 `./gradlew generateProto compileJava` 가 통과한다 (`WarrantProtos` · `AuditProtos` ·
`AgentProtos` · `*ServiceGrpc`). Go · C 쪽 생성물은 아직 없다.

## 초안이 정한 것 — 골격 주석과 다른 지점

- **취소는 별도 메시지가 아니다.** `revoked=true` · `revision+1` 인 새 `SignedWarrant` 를 내린다.
  경로가 하나라야 "취소만 서명 검증을 안 한다" 같은 구멍이 안 생긴다.
- **`revision` 이 있다.** 노드는 자기가 가진 것보다 큰 revision 만 적용한다. 취소 뒤 옛 봉투를
  다시 밀어 넣는 재생을 막는다.
- **`warrant_id` 는 u64 이고 서버가 발급하며 재사용하지 않는다.** UUID 는 `warrant_uuid` 로 따로 싣는다.
  `Warrant` 엔티티에 이 u64 컬럼을 추가해야 한다.
- **유예는 기간(`grace_window_ns`)이다.** 절대시각(`grace_until`)이 아니다 — 연장으로 `expires_at` 이 밀리면
  유예 창도 따라가야 하고, 커널 `grace_ns` 도 기간이다. 엔티티의 `graceUntil` 은 파생값이 된다.
- **정책은 영장 안에 인라인으로 들어가 함께 서명된다.** 노드가 정책만 바꿔치기할 수 없다.
- **`login_account` 가 영장에 있다.** T1 바인딩에서 PAM 이 넘긴 계정과 활성 영장을 잇는 키다.
- **감사 스트림은 양방향이다.** ack 를 중간중간 돌려줘야 하므로 클라이언트 스트리밍(응답 1회)으로는 안 된다.
- **Java 는 `java_multiple_files=false`.** `Warrant` · `AuditEvent` 가 도메인 클래스와 이름이 겹쳐서
  `WarrantProtos.Warrant` 로 쓴다.
- `go_package` 는 `agent/` 에 `go.mod` 가 생기면 그때 맞춘다.

## 검토에서 고친 것 (2026-09-09)

- **커널 폭을 맞췄다.** `FileRef.dev` 는 `s_dev`(= `dev_t`, **u32**)라 `fixed32`,
  `pid_ns_inum`·`mnt_ns_inum` 은 `ns_common.inum`(= `unsigned int`)이라 `fixed32`.
  셋 다 `fixed64` 였다 — 아래 「규칙」의 고정폭 원칙을 스스로 어긴 자리였고, 이게 정확히
  "커널 구조체와 서버 엔티티가 어긋나면 디버깅이 지옥"이라던 그 클래스다.
- **`AuditEvent.mode` 추가.** `VERDICT_WOULD_DENY` 만으로는 OBSERVE 인지 DRYRUN 인지
  모른다. §15 가 요구하는 "감사·강제가 판정 함수를 공유한다"를 검증하려면 같은
  입력에 두 모드가 같은 verdict 를 냈는지 대조해야 하고, mode 없이는 못 한다.
- **`AuditEvent.origin` 추가.** `lsm/*` 인가 `kprobe/security_*` 미러인가. 같은
  판정 함수를 부르므로 결과가 같아야 하고, 다르면 그 사실을 짚어야 한다.
- **`AuditEvent` 필드 번호를 다시 매겼다.** 번호 16 이상은 태그가 2바이트인데
  전건에 실리는 `process`(20)와 `payload`(30~43)가 거기 있었다. 초당 수백~수천 건이
  흐르는 메시지다 — 그룹 경계보다 바이트가 우선이라 `process`=13, 고빈도 payload
  (`exec`·`file_write`)를 14·15 로 내렸다.
- **`WriteRule` 우선순위를 못 박았다.** ALLOW 와 DENY 가 한 목록에 섞여 있는데
  어느 쪽이 이기는지 없었다. **최장 일치 → 같으면 DENY → 안 걸리면 금지.**
  이게 없으면 §15 가 요구하는 "디렉터리 금지 + 그 안의 파일 허용"을 표현할 수 없고,
  세 계층이 서로 다르게 구현한다.
- **`NetRule.proto` 추가** (`PROTO_ANY`/`TCP`/`UDP`). `cidr`+`port` 만으로는
  "TCP 443 허용, UDP 443 금지"를 못 쓴다. §18 의 UDP 구멍이 있는데 그 축이 없었다.
  `inspect_udp` 는 "볼 것인가"고 이건 "허용할 것인가"라 다른 축이다.
- **`read_watch_paths` 를 `inspect_udp` 와 같은 취급으로 가뒀다.** 문서에 근거가
  없는 필드였고, S1 실측과 부딪친다 — 읽기 경로를 감시하면 `f_mode & FMODE_WRITE`
  앞문이 무력화되고 `w_find` 기준 0.31% → 1.7%(5배)가 된다. **목록이 비어 있으면
  BPF 프로그램이 읽기 경로를 아예 보지 않는다**는 규칙을 주석에 박았고,
  실제 구현 전에 `bench/overhead` 에 티어를 추가해 재기로 했다.

## 미해결 — 확정 전에 답해야 한다

### 1. 공유 계정에서 사람을 어떻게 가르나 ★

`LookupRequest{hostname, login_account}` → `repeated SignedWarrant`.
**`ec2-user` 로 두 사람이 동시에 영장을 받으면 PAM 이 어느 쪽인지 모른다.**

이건 제품의 출발점과 직접 부딪친다. 기획서 §01:

> **귀속이 무너진다** — 전부 `ec2-user` 로 들어와 `sudo` 를 친다.

그 문제를 풀겠다는 제품인데 지금 스키마로는 동시 접속을 못 가른다.
`login_account` 주석 스스로도 "신원이 아니라 참고 정보"라고 적어놓고 바인딩
키로 쓰고 있다. 기획서에도 답이 없다.

현실적 해법은 SSH 공개키 지문이나 인증서 principal 을 PAM 이 읽어 넘기는 것인데
(`sshd` 의 `AuthorizedKeysCommand` · `PAM_AUTHTOK` 경로), **그러려면
`LookupRequest` 에 그 필드가 있어야 한다.** 지금은 자리가 아예 없다.

**나중에 넣으면 세 계층이 다 그 위에 붙은 뒤가 된다.** `.proto` 확정을 스파이크
뒤로 미룬 것과 같은 이유로, 이건 확정 전에 정한다.

### 2. `read_watch_paths` 를 실제로 넣을 것인가

넣는다면 `bench/overhead` 에 읽기 감시 티어를 추가해 재고 나서다.
안 넣는다면 필드를 지우고 번호를 `reserved` 로 박제한다.

### 3. `WriteRule` 최장 일치를 커널에서 어떻게 구현하나

필드 문서 §07 이 "조상 체인 순회가 비용의 전부"라고 지목한 지점이다.
조상 inode 를 위로 훑으며 처음 만나는 규칙이 최장 일치 — 맞는데, **몇 단계까지
훑을 것인가**가 정해져 있지 않다. BPF 루프 상한이 있으므로 깊이 제한이 필요하고,
제한을 넘는 경로에서 어떻게 판정할지(막을지 통과시킬지)를 정해야 한다.
S1 이 잰 것은 조상 순회 **없는** 판정이다 — 순회를 넣으면 다시 재야 한다.

## 규칙

- **서명은 protobuf 직렬화 바이트에 한다.** JSON 서명은 키 순서·공백 정규화 문제를 만든다.
  서명한 바이트를 그대로 저장하고 그대로 전송한다 — 재직렬화하면 서명이 깨진다.
- 시간 필드는 두 좌표계가 섞인다. 중앙은 **절대시각**(`expires_at`, Unix ns)을 보내고,
  커널의 `expires_ns` 는 **노드별 boot 기준**이다. 변환은 warrantd 가 한다 — proto 에 boot 기준 값을 넣지 말 것.
- 필드 번호는 재사용하지 않는다. 지운 번호는 `reserved` 로 박제한다.
- 커널 구조체에 그대로 매핑되는 메시지는 **고정폭 정수만** 쓴다(`fixed64`/`uint32`).
  varint 는 BPF 쪽에서 파싱할 수 없다.

## 필드 메모 — .proto 에서 옮겨 온 것

`.proto` 주석은 필드당 한 줄로 줄였다. 한 줄에 안 들어가는 근거는 여기 둔다.

- **C 폭 대응**: `fixed64` ↔ `__u64` · `uint32`/`fixed32` ↔ `__u32` · enum ↔ `__u8`.
  `FileRef.dev` 는 `s_dev`(u32), `ino` 는 `unsigned long`(x86_64 에서 u64), ns inum 은 `unsigned int`.
- **`warrant_id` 재사용 금지**: 재사용하면 과거 감사 로그의 귀속이 조용히 뒤바뀐다. `AuditEvent.warrant_id = 0` 은 "없음"의 자리라 서버는 0 을 발급하지 않는다.
- **`target_hosts`**: 서버는 목록의 노드에만 push 하고, 노드는 자기 hostname 이 없으면 봉투를 거부한다(잘못 배달된 영장 방어).
- **`break_glass`**: warrantd 는 이 플래그가 켜진 봉투를 받는 즉시 최고 등급 경보를 올린다.
- **`WriteRule` 최장 일치의 커널 구현**: 자기 inode 에서 조상 체인을 위로 훑어 가장 먼저 만나는 규칙. 깊이 상한은 미해결 3.
- **`ProcessIdentity.ppid`**: `parent` 가 아니라 `real_parent` — ptrace 중이면 둘이 갈린다.
- **`FileRef.dev`**: 컨테이너 overlayfs 에서는 호스트와 다른 값이 나온다. `path` 는 `bpf_d_path` 가 비싸서 차단 건에만 채운다.
- **`InodeMutateEvent`**: rename 은 언제나 양방향 판정이다 — 한쪽만 보면 뚫린다.
- **`AuditEvent.tag_source = TAG_TASK`**: cgroup 을 벗어난 프로세스를 2차 방어선이 잡았다는 흔적이다(S2 의 `systemd-run --scope`).
- **`ForkEvent`**: 볼륨이 커서 제품 기본값은 기록하지 않는다. S2 재검증 · 디버깅용.
- **`LookupActiveWarrant`**: PAM 질의에 답하는 것은 warrantd 캐시다. 중앙이 인증 경로에 끼면 중앙 장애가 곧 로그인 장애가 되므로 여기에 기대지 않는다.
- **`AuditBatch.gaps`**: 별도 채널이면 순서가 어긋나 "이벤트가 있었는데 gap 도 있다"가 된다.
- **`NodeHello.attached_hooks`**: 훅을 하나씩 붙이는 동안 "이 노드는 file_open 을 아직 안 본다"를 서버가 알아야 빈 데이터를 오해하지 않는다.

## 생성물

- Java: `server/build.gradle` 의 `sourceSets.main.proto` 가 이 디렉터리를 참조한다 (protobuf-gradle-plugin).
- Go: `agent/` 에서 `protoc-gen-go` · `protoc-gen-go-grpc`.
- C: BPF 쪽은 protobuf 를 쓰지 않는다. `bpf/warrant.bpf.h` 의 `struct warrant` 를 **손으로** 맞추고,
  일치 여부는 테스트로 지킨다(필드 오프셋 assert).
