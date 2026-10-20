# warrant-server

Session Warrant 의 컨트롤 플레인. 영장 발급 · 승인 · 서명 · push · 취소 · 감사 조회를 담당한다.

**현재 상태: 요구사항 골격.** 모든 클래스가 시그니처와 의사코드 주석만 갖고 있고 본문은 비어 있다.
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

```
io.seswar.warrant
├── domain/       엔티티 · 값 객체 · 도메인 규칙 (warrant · policy · subject · node · audit)
├── application/  유스케이스 서비스 (발급 · 연장 · 취소 · 승인 · 감사 수집 · 무영장 탐지)
├── crypto/       Ed25519 서명 — protobuf 바이트에 서명한다
├── grpc/         warrantd 와의 통신 (영장 push = 서버 스트리밍, 감사 = 클라이언트 스트리밍)
├── api/          REST — 콘솔(신청 · 승인 큐 · 연장 · 회수) · 리포트
├── repository/   Spring Data JPA
└── config/       Security(OIDC) · gRPC · 가상 스레드
```

## 신청 · 승인 — 콘솔 자체 경로

영장 신청과 승인은 **콘솔(웹)에서 한다.** 외부 메신저 연동은 두지 않는다 (2026-10-16 결정).
이번 학기 범위 밖이라(루트 `CLAUDE.md` 범위표) API 는 골격만 있다.

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
3. 발급 → 서명 → push 경로 (`WarrantIssuanceService` → `WarrantSigner` → `WarrantPushService`)
4. 감사 수집 (`AuditIngestService`) 및 무영장 세션 탐지
5. 콘솔 신청 · 승인 큐 · 연장 정책
