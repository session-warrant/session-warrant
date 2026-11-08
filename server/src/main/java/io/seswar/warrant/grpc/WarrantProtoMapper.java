package io.seswar.warrant.grpc;

import io.seswar.warrant.domain.policy.ExecRule;
import io.seswar.warrant.domain.policy.NetRule;
import io.seswar.warrant.domain.policy.Policy;
import io.seswar.warrant.domain.policy.WriteRule;
import io.seswar.warrant.domain.subject.Subject;
import io.seswar.warrant.domain.warrant.Warrant;
import io.seswar.warrant.proto.WarrantProtos;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Comparator;

/**
 * 도메인 ↔ protobuf 변환.
 *
 * <p>{@code Instant expiresAt} → {@code u64 expires_ns} 변환은 <b>하지 않는다</b>.
 * 커널의 {@code expires_ns} 는 노드마다 다른 부팅 상대 시각이라 중앙이 계산할 수 없다 —
 * wire 에는 <b>절대 시각</b>을 싣고 변환은 warrantd 가 한다.
 *
 * <p>모든 목록을 정렬해서 싣는다. 노드는 같은 {@code policy_id} 의 규칙이 영장마다 다르면 거부하는데,
 * protobuf 는 repeated 순서까지 비교한다 — Set 순서 그대로 실으면 같은 정책이 다르게 보일 수 있다.
 */
@Component
public class WarrantProtoMapper {

    /** @return 서명 대상이 될 직렬화 바이트 */
    public byte[] toSignedBytes(Warrant w, Subject subject, Policy policy) {
        return WarrantProtos.Warrant.newBuilder()
                .setWarrantId(w.getWarrantId())
                .setWarrantUuid(w.getId().toString())
                .setDisplayId(w.getDisplayId())
                .setRevision(w.getRevision())
                .setSubjectId(subject.getKernelSubjectId())
                .setPrincipal(subject.getPrincipal())
                .setLoginAccount(w.getLoginAccount())
                .addAllSshKeyFingerprints(w.getSshKeyFingerprints().stream().sorted().toList())
                .addAllTargetHosts(w.getTargetHosts().stream().sorted().toList())
                .setReason(w.getReason())
                .setIssuedAtUnixNs(unixNs(w.getIssuedAt()))
                .setExpiresAtUnixNs(unixNs(w.getExpiresAt()))
                .setGraceWindowNs(w.getGraceWindow().toNanos())
                .setRevoked(w.isRevoked())
                .setModeValue(w.getMode().wireValue())
                .setOnExpiryValue(w.getOnExpiry().wireValue())
                .setPolicyId(policy.getKernelPolicyId())
                .setPolicy(toProto(policy))
                .setBreakGlass(w.isBreakGlass())
                .build()
                .toByteArray();
    }

    private static WarrantProtos.Policy toProto(Policy p) {
        WarrantProtos.Policy.Builder b = WarrantProtos.Policy.newBuilder()
                .setName(p.getName())
                .setInspectUdp(p.isInspectUdp())
                .addAllReadWatchPaths(p.getReadWatchPaths().stream().sorted().toList());
        p.getExecRules().stream().map(ExecRule::path).sorted()
                .forEach(path -> b.addExecRules(WarrantProtos.ExecRule.newBuilder().setPath(path)));
        p.getWriteRules().stream().sorted(Comparator.comparing(WriteRule::path))
                .forEach(r -> b.addWriteRules(WarrantProtos.WriteRule.newBuilder()
                        .setPath(r.path())
                        .setRecursive(r.recursive())
                        .setEffectValue(r.effect().wireValue())));
        p.getNetRules().stream()
                .sorted(Comparator.comparing(NetRule::cidr).thenComparingInt(NetRule::port)
                        .thenComparing(r -> r.proto().wireValue()))
                .forEach(r -> b.addNetRules(WarrantProtos.NetRule.newBuilder()
                        .setCidr(r.cidr())
                        .setPort(r.port())
                        .setProtoValue(r.proto().wireValue())));
        return b.build();
    }

    private static long unixNs(Instant t) {
        return t.getEpochSecond() * 1_000_000_000L + t.getNano();
    }
}
