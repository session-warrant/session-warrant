package io.seswar.warrant.api;

import io.seswar.warrant.domain.policy.ExecRule;
import io.seswar.warrant.domain.policy.NetRule;
import io.seswar.warrant.domain.policy.Policy;
import io.seswar.warrant.domain.policy.WriteRule;
import io.seswar.warrant.repository.PolicyRepository;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * 정책 등록 · 목록. 한 행 = 한 버전이고 고치지 않는다 — 바꾸려면 새로 만든다.
 * 아직 없는 것: {@code POST /api/policies/{id}/lint} (실행 · 쓰기 허용 조합 경고, §04).
 */
@RestController
@RequestMapping("/api/policies")
@RequiredArgsConstructor
public class PolicyController {

    private final PolicyRepository policies;

    // Boxed fields: Jackson 3 rejects a missing primitive, and every field but name may be left out.
    public record CreatePolicy(@NotBlank String name, Boolean inspectUdp, List<String> execRules,
                               List<WriteRuleBody> writeRules, List<NetRuleBody> netRules) {
    }

    /** {@code effect} 는 반드시 적는다 — 빠뜨린 DENY 가 ALLOW 로 읽히면 안 된다. */
    public record WriteRuleBody(String path, Boolean recursive, WriteRule.Effect effect) {
        WriteRule toRule() {
            if (path == null || effect == null) {
                throw new IllegalArgumentException("write rule needs path and effect");
            }
            return new WriteRule(path, Boolean.TRUE.equals(recursive), effect);
        }
    }

    /** port 를 안 적으면 0(전체), proto 를 안 적으면 ANY. */
    public record NetRuleBody(String cidr, Integer port, NetRule.Proto proto) {
        NetRule toRule() {
            if (cidr == null) {
                throw new IllegalArgumentException("net rule needs cidr");
            }
            return new NetRule(cidr, port == null ? 0 : port, proto == null ? NetRule.Proto.ANY : proto);
        }
    }

    // Not the domain records: Jackson would call their is*() lint methods as properties.
    public record PolicyView(UUID id, int kernelPolicyId, String name, boolean inspectUdp,
                             List<String> execRules, List<WriteRuleBody> writeRules, List<NetRuleBody> netRules) {
        static PolicyView of(Policy p) {
            return new PolicyView(p.getId(), p.getKernelPolicyId(), p.getName(), p.isInspectUdp(),
                    p.getExecRules().stream().map(ExecRule::path).sorted().toList(),
                    p.getWriteRules().stream().sorted(Comparator.comparing(WriteRule::path))
                            .map(r -> new WriteRuleBody(r.path(), r.recursive(), r.effect())).toList(),
                    p.getNetRules().stream().sorted(Comparator.comparing(NetRule::cidr))
                            .map(r -> new NetRuleBody(r.cidr(), r.port(), r.proto())).toList());
        }
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public PolicyView create(@Valid @RequestBody CreatePolicy body) {
        List<ExecRule> exec = orEmpty(body.execRules()).stream().map(ExecRule::new).toList();
        List<WriteRule> write = orEmpty(body.writeRules()).stream().map(WriteRuleBody::toRule).toList();
        List<NetRule> net = orEmpty(body.netRules()).stream().map(NetRuleBody::toRule).toList();
        return PolicyView.of(policies.saveAndFlush(
                Policy.of(body.name(), Boolean.TRUE.equals(body.inspectUdp()), exec, write, net)));
    }

    @GetMapping
    public List<PolicyView> list() {
        return policies.findAll().stream().map(PolicyView::of).toList();
    }

    private static <T> List<T> orEmpty(List<T> l) {
        return Objects.requireNonNullElse(l, List.of());
    }
}
