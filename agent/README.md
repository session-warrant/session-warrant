# agent/

Go 1.25+ · `warrantd`. 노드 에이전트.
cilium/ebpf v0.22 · bpf2go · grpc-go · bbolt · x/sys/unix.

Rust(aya) 가 아니라 Go 인 이유는 성능이 아니라 **막혔을 때 검색으로 풀리는가**다.

## 구조

```
cmd/warrantd/       main. 플래그 · 시그널 · 종료
internal/loader/    BPF 오브젝트 로드 · bpffs pin · 훅 attach
internal/bpfmap/    맵 R/W 래퍼 (warrants · task_warrant · allow/deny · config)
internal/pamsock/   PAM 유닉스 소켓 수신 → cgroup id 태깅
internal/policy/    경로 → (dev, ino) 컴파일. fanotify 로 재컴파일 감시
internal/ringbuf/   ringbuf consumer → 감사 이벤트 · dropped 카운터
internal/upstream/  중앙 gRPC 클라이언트 (발급 push 수신 · 감사 업로드)
internal/store/     bbolt. 중앙이 끊긴 동안의 영장·감사 로컬 보관
internal/pb/        proto/*.proto 생성물 (커밋한다)
bpf/                bpf2go 생성물 (커밋한다)
```

## 소유 (2026-09-23 재배치)

| 패키지 | 담당 |
|---|---|
| `loader` · `bpfmap` · `ringbuf` · `policy` | A · 김강민 (커널) |
| `upstream` · `store` | B · 장지은 (서버·계약) |
| `pamsock` · `cmd/warrantd` | C · 김종혁 (노드 통합) |

**A ↔ B 의 경계는 gRPC 가 아니라 `bpfmap` 의 맵 레이아웃 하나다.** `upstream` 은 맵을 직접
열지 않고 `bpfmap` 함수만 부른다. 값 구조체는 `proto/warrant.proto` 에서 나온다.

## 상태

**골격만 있다.** 패키지와 시그니처·주석은 있고 본문은 전부 `panic("미구현")` 이다.
의존성도 아직 없다 — `go.mod` 에 require 가 비어 있고 표준 라이브러리만 쓴다.
`go build ./...` · `go vet ./...` 는 통과한다.

cilium/ebpf · grpc-go · bbolt 는 해당 패키지를 실제로 구현할 때 각자 추가한다.

## 규칙

- **중앙이 끊겨도 이미 발급된 영장의 집행은 계속된다.** warrantd 가 죽어도 마찬가지다 —
  판정은 커널이 혼자 한다. warrantd 는 발급·감사 수집만 담당한다 (§10, §17).
- **시간 좌표 변환은 여기서만 한다.** 중앙은 절대시각을 주고, 커널 `expires_ns` 는 boot 기준이다.
  노드 boot time 을 읽어 변환한다. 이 변환이 다른 계층에 새면 안 된다.
- **경로 → inode 컴파일도 여기서만 한다.** 커널은 `(dev, ino)` 만 안다.
  금지 규칙이 파일 inode 로 컴파일되면 **거부**한다 — 디렉터리 inode 여야 한다 (§15).
- 재시작 중 태깅 공백이 생기면 안 된다. 맵·프로그램은 bpffs pin, systemd 유닛에 `Before=sshd.service`.
- 감사 유실은 숨기지 않는다. `dropped` 카운터를 그대로 올려보내고 유실 구간을 명시한다 (§13).
- bpf2go 생성물은 **커밋한다.** 빌드 머신에 clang 이 없어도 `go build` 가 서야 한다.
