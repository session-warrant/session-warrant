package io.seswar.warrant.application;

import io.seswar.warrant.domain.warrant.Warrant;

import java.util.UUID;

/** 영장의 T0 · 발급(§11). 승인 → 서명 → 대상 호스트의 warrantd 로 push. */
// @Service @Transactional
public class WarrantIssuanceService {

    /**
     * 승인 요청 생성. 아직 서명하지 않고 노드로도 내려가지 않는다.
     */
    public Warrant request(IssueWarrantCommand cmd, UUID requesterId) {
        // 1. 주체 · 정책 · 대상 호스트 존재 확인
        // 2. PolicyLinter.lint()  — ERROR 면 여기서 거부한다. 승인자에게 올리지도 않는다
        // 3. PolicyLinter.assertDoesNotWeakenSelfProtection() — §16 을 여는 정책은 발급 불가
        // 4. 대상 노드 중 bpfLsmEnabled=false 가 있고 mode=ENFORCE 면
        //    "이 노드에서는 강제되지 않음"을 요청에 명시적으로 붙인다. 조용히 넘기지 말 것
        // 4b. (subject, 대상 호스트, loginAccount) 에 활성 영장이 이미 있으면 이 요청은 그걸 "대체"한다고
        //     명시한다. 활성 1개 불변식 — 모호함이 노드까지 내려가면 warrantd 가 고를 규칙이 없다
        // 5. onExpiry.requiresGraceWindow() 인데 graceWindow 가 없으면 거부 — 무기한 유예는 존재하지 않는다
        // 6. state = REQUESTED, lineage += REQUESTED
        // 7. ApprovalService 로 승인 요청 전달
        throw new UnsupportedOperationException("미구현");
    }

    /**
     * 승인 후 발급. 서명 → 저장 → push 순서로 간다.
     */
    public Warrant issue(UUID warrantId, UUID approverId) {
        // 1. state 가 REQUESTED 인지 확인 (중복 승인 방지)
        // 2. expiresAt = now + duration  — 발급 시점 기준이다. 승인이 늦어졌다고 요청 시각 기준으로 잡으면
        //    이미 만료된 영장이 나온다
        // 2b. warrantId 는 시퀀스에서 새로 받는다(0 · 재사용 금지). revision = 1.
        //     sshKeyFingerprints 는 Subject 에서 이 시점에 스냅샷한다
        // 2c. 대체할 기존 영장이 있으면 같은 트랜잭션에서 취소 revision 을 만든다 (subject 행 FOR UPDATE)
        // 3. WarrantProtoMapper 로 protobuf 메시지 생성 → 직렬화
        // 4. WarrantSigner.sign(bytes)  — JSON 이 아니라 이 바이트에 서명한다
        // 5. state = ISSUED, lineage += ISSUED (승인자 · 사유 · 원 기간)
        // 6. 저장 커밋 후 WarrantPushService.push()
        //    순서 주의: push 먼저 하고 저장이 실패하면 노드에만 존재하는 유령 영장이 생긴다
        //    대체한 영장이 있으면 그 취소 revision 을 <b>먼저</b> push 한다. 같은 스트림이라 순서가 보장되고,
        //    노드에 한순간이라도 활성 영장 둘이 겹치지 않는다
        throw new UnsupportedOperationException("미구현");
    }

    /**
     * 누적 상한에 걸린 연장 요청을 재발급으로 처리한다.
     * 연장이 아니라 <b>새 사유 · 새 승인</b>이 붙는 별개의 영장이다(§03).
     */
    public Warrant reissue(UUID exhaustedWarrantId, IssueWarrantCommand cmd, UUID requesterId) {
        // 원 영장의 계보에 REISSUED 를 남기고 새 영장의 계보에 원 영장을 참조로 남긴다.
        // 감사에서 두 영장이 한 작업의 연속임을 읽을 수 있어야 한다.
        throw new UnsupportedOperationException("미구현");
    }
}
