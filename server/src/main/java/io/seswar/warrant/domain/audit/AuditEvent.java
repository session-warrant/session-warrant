package io.seswar.warrant.domain.audit;

import java.time.Instant;
import java.util.UUID;

/**
 * 감사 레코드 한 건. 커널 ringbuf → warrantd → gRPC 로 여기 도착한다.
 *
 * <p>남는 것(§14) — 실행된 모든 프로세스, 자원에 손댄 순간.
 * 안 남는 것 — 셸 빌트인({@code cd}), 인터프리터 내부 로직, 파일 읽기, 터미널 입력.
 */
// @Entity @Table(name = "audit_event")  // PARTITION BY RANGE (occurred_at)
public class AuditEvent {

    private UUID id;

    private Instant occurredAt;

    private UUID nodeId;

    /** null 이면 영장 없는 프로세스. 그 자체가 조사 대상이다. */
    private UUID warrantId;

    /** 커널이 들고 있던 u32. 조회 시점에 사람 이름으로 조인된다. */
    private Integer kernelSubjectId;

    private AuditEventType type;

    private Verdict verdict;

    private long pid;

    private long cgroupId;

    /** sudo 뒤의 uid. 신원이 아니라 정황 정보다 — 신원은 warrantId 쪽에 있다. */
    private int uid;

    /** 커널이 실제로 연 파일의 {@code (dev, ino)}. <b>신뢰의 근거는 이것이다.</b> */
    private long deviceId;

    private long inode;

    /** 해석된 경로. 리포트 가독성을 위한 참고 정보이며 증거로 쓰지 않는다. */
    private String resolvedPath;

    /**
     * 명령줄 인자. <b>1급 증거가 아니다</b>(§14) — BPF 스택 제약으로 잘리고
     * {@code exec -a} 한 줄이면 argv[0] 이 위조된다.
     */
    private String argvTruncated;

    /** CONNECT · UDP_SEND 일 때의 목적지. AF_UNIX 면 sun_path. */
    private String destination;
}
