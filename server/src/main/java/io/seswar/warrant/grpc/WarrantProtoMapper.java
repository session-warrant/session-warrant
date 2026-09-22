package io.seswar.warrant.grpc;

import io.seswar.warrant.domain.warrant.Warrant;

/**
 * 도메인 ↔ protobuf 변환.
 *
 * <p>{@code Instant expiresAt} → {@code u64 expires_ns} 변환은 <b>하지 않는다</b>.
 * 커널의 {@code expires_ns} 는 노드마다 다른 부팅 상대 시각이라 중앙이 계산할 수 없다 —
 * wire 에는 <b>절대 시각</b>을 싣고 변환은 warrantd 가 한다.
 */
// @Component
public class WarrantProtoMapper {

    /** @return 서명 대상이 될 직렬화 바이트 */
    public byte[] toSignedBytes(Warrant warrant) {
        // WarrantProtos.Warrant.newBuilder()
        //     .setWarrantId(warrantId)             // u64 커널 맵 키
        //     .setWarrantUuid(id) .setDisplayId(displayId) .setRevision(revision)
        //     .setSubjectId(...)                   // u32 — Subject.kernelSubjectId
        //     .setPrincipal(...) .setLoginAccount(loginAccount) .addAllSshKeyFingerprints(...)
        //     .addAllTargetHosts(...) .setReason(reason)
        //     .setIssuedAtUnixNs(...) .setExpiresAtUnixNs(...)   // 절대 시각. boot 기준 변환은 노드에서
        //     .setGraceWindowNs(graceWindow.toNanos())           // 기간이다. graceUntil 아님
        //     .setRevoked(revoked) .setModeValue(mode.wireValue()) .setOnExpiryValue(onExpiry.wireValue())
        //     .setPolicyId(policy.kernelPolicyId)  // u32 버전 id
        //     .setPolicy(...)                      // Effect 는 wireValue() — 0(UNSPECIFIED)을 만들지 말 것
        //     .setBreakGlass(breakGlass)
        //     .build().toByteArray()
        throw new UnsupportedOperationException("미구현");
    }
}
