package io.seswar.warrant.domain.node;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

/** 영장을 집행하는 호스트. warrantd 한 대가 한 노드다. */
// @Entity @Table(name = "node")
public class Node {

    private UUID id;

    /**
     * mTLS 클라이언트 인증서 지문. <b>노드 신원은 이것이다</b> — 감사 멱등 키
     * {@code (node_id, seq_epoch, node_seq)} 의 node_id 는 이 값으로 찾은 {@link #id} 다.
     * {@code NodeHello.hostname} 은 노드 자기 신고라 키로 쓰지 않는다.
     */
    private String clientCertFingerprint;

    /** 노드가 신고한 hostname. 인증서의 것과 다르면 경보한다. */
    private String hostname;

    private String kernelVersion;

    /**
     * BPF LSM 이 켜져 있는가 ({@code /sys/kernel/security/lsm} 에 bpf 포함).
     * false 면 이 노드에서는 ENFORCE 영장을 발급해도 강제되지 않는다 —
     * <b>발급 시점에 거부하거나 최소한 승인자에게 알려야 한다</b>. 조용히 통과시키면
     * "막고 있다고 믿는데 안 막히는" 최악의 상태가 된다.
     */
    private boolean bpfLsmEnabled;

    private String agentVersion;

    /**
     * 지금 붙어 있는 훅 ({@code NodeHello.attached_hooks}). 훅을 하나씩 붙이는 동안
     * "이 노드는 file_open 을 아직 안 본다"를 알아야 빈 데이터를 "아무 일 없음"으로 오해하지 않는다.
     */
    private Set<String> attachedHooks;

    /** 현재 감사 seq epoch. bbolt 가 초기화되면 바뀐다 — 바뀐 사실 자체가 조사 대상이다. */
    private Long currentSeqEpoch;

    /** 마지막 하트비트. gRPC 스트림이 살아 있는지와는 별개로 기록한다. */
    private Instant lastSeenAt;

    /**
     * 노드 부팅 시각. {@code Instant} → {@code bpf_ktime_get_boot_ns} 변환의 기준이지만
     * <b>변환은 warrantd 가 한다</b>. 여기 값은 시계 스큐 진단용 참고 정보일 뿐이다.
     */
    private Instant bootedAt;
}
