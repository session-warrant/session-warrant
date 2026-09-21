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
        // WarrantProto.newBuilder()
        //     .setWarrantId(...)      // display id 와 내부 UUID 를 둘 다 싣는다
        //     .setSubjectId(...)      // u32 — Subject.kernelSubjectId
        //     .setPolicyId(...)       // u32
        //     .setExpiresAtEpochMillis(...)   // 절대 시각. ns 변환은 노드에서
        //     .setGraceUntilEpochMillis(...)
        //     .setRevoked(...)
        //     .setMode(mode.wireValue())
        //     .setOnExpiry(onExpiry.wireValue())
        //     .addAllExecRules(...) .addAllWriteRules(...) .addAllNetRules(...)
        //     .build().toByteArray()
        throw new UnsupportedOperationException("미구현");
    }
}
