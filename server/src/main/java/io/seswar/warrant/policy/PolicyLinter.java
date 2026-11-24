package io.seswar.warrant.policy;

import io.seswar.warrant.policy.PolicyLintFinding.Severity;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * 정책 설계 원칙(§04)을 코드로 강제하는 곳.
 *
 * <p><b>실행 허용 목록과 쓰기 허용 목록은 반드시 함께 검토해야 한다.</b>
 * 운영상 {@code systemctl restart} 를 허용해야 하는 영장이라면,
 * {@code /etc/systemd/system} 쓰기를 같이 열어주는 순간 임의 코드 실행 경로가 생긴다.
 * 둘 중 하나만 보고는 안전을 보장할 수 없다.
 *
 * <p>심각도(팀 결정, 2026-11):
 * <ul>
 *   <li><b>ERROR</b> — 정책 등록과 영장 신청을 400 으로 거부한다.
 *       {@code SELF_PROTECTION_TOUCH} · {@code EXEC_WRITE_COMBO}</li>
 *   <li><b>WARN</b> — 저장은 하고 정책 응답과 승인 큐에 같이 내린다. 승인자가 보고 판단한다.
 *       {@code NET_WIDE_OPEN} · {@code SCOPE_TOO_WIDE} · {@code RISKY_WRITE} · {@code EXEC_IN_WRITABLE_DIR}</li>
 * </ul>
 * ERROR 는 커널 집행이 아니라 서버의 입력 검사다 — 감사 모드에서도 사람의 접속은 막지 않고,
 * 그 정책으로 서명된 영장이 나가지 않을 뿐이다.
 *
 * <p>검사하지 않는 것:
 * <ul>
 *   <li>{@code DENY_ON_FILE_INODE} — 금지 규칙이 파일을 가리키는지는 노드의 파일 시스템을 봐야 안다.
 *       서버는 경로 문자열만 가지므로 판단하지 않고, warrantd 가 컴파일 때 거부한다
 *       ({@code agent/internal/policy.ErrDenyOnFile}).</li>
 *   <li>인터프리터 + 그 인터프리터가 읽는 경로 쓰기 — 경로 목록을 정의할 수 없어 이번 학기 범위 밖이다.</li>
 * </ul>
 */
@Component
public class PolicyLinter {

    public static final String SELF_PROTECTION_TOUCH = "SELF_PROTECTION_TOUCH";
    public static final String EXEC_WRITE_COMBO = "EXEC_WRITE_COMBO";
    public static final String NET_WIDE_OPEN = "NET_WIDE_OPEN";
    public static final String SCOPE_TOO_WIDE = "SCOPE_TOO_WIDE";
    public static final String RISKY_WRITE = "RISKY_WRITE";
    public static final String EXEC_IN_WRITABLE_DIR = "EXEC_IN_WRITABLE_DIR";

    public List<PolicyLintFinding> lint(Policy policy) {
        List<PolicyLintFinding> out = new ArrayList<>();
        selfProtection(policy, out);
        execWriteCombo(policy, out);
        netWideOpen(policy, out);
        scopeTooWide(policy, out);
        riskyWrites(policy, out);
        return out;
    }

    /** lint 결과에 ERROR 가 하나라도 있으면 400 (ApiErrors 가 IllegalArgumentException 을 400 으로 바꾼다). */
    public void assertNoErrors(Policy policy) {
        String errors = lint(policy).stream()
                .filter(f -> f.severity() == Severity.ERROR)
                .map(f -> f.code() + ": " + f.message())
                .collect(Collectors.joining("; "));
        if (!errors.isEmpty()) {
            throw new IllegalArgumentException("policy rejected by lint — " + errors);
        }
    }

    /** 승인자에게 보여줄 경고만. */
    public List<PolicyLintFinding> warnings(Policy policy) {
        return lint(policy).stream().filter(f -> f.severity() == Severity.WARN).toList();
    }

    /**
     * 자기 보호 6종(§16)은 <b>정책이 아니라 제품이 강제로 삽입하는 기본 규칙</b>이다.
     * 영장 작성자가 실수로든 고의로든 열 수 없어야 하고, 하나라도 열리면 나머지가 무의미해진다.
     *
     * <p>따라서 이 메서드는 "경고"가 아니라 <b>발급 거부</b>로 이어져야 한다.
     * 유일한 예외는 break-glass 영장이며, 그건 별도 경로로 최고 등급 경보와 함께 발급된다.
     */
    public void assertDoesNotWeakenSelfProtection(Policy policy) {
        List<PolicyLintFinding> out = new ArrayList<>();
        selfProtection(policy, out);
        if (!out.isEmpty()) {
            throw new IllegalArgumentException(out.getFirst().message());
        }
    }

    // ── SELF_PROTECTION_TOUCH (ERROR) ────────────────────────────────────────────

    private static void selfProtection(Policy policy, List<PolicyLintFinding> out) {
        // 여섯 중 다섯(bpf · task_kill · sb_umount · ptrace_access_check · kernel_module_request)은
        // 규칙 조회가 없는 LSM 훅이라 정책으로는 열 수 없다(bpf/warrant.bpf.c 「자기보호 5종」).
        // 정책이 열 수 있는 건 여섯 번째뿐이다 — warrantd 자기 파일 쓰기 금지는 agent/internal/policy 가
        // 깔아 두는 DENY 규칙이고, 정책의 같은 경로 ALLOW 는 뒤에 들어가 이기고(같은 키),
        // 그 아래 경로 ALLOW 는 최장 일치로 이긴다. 그래서 그 두 모양만 막으면 된다.
        for (WriteRule r : policy.getWriteRules()) {
            if (r.effect() != WriteRule.Effect.ALLOW) {
                continue;
            }
            String path = normalize(r.path());
            for (String dir : SELF_PROTECTED_DIRS) {
                if (within(path, dir)) {
                    out.add(new PolicyLintFinding(Severity.ERROR, SELF_PROTECTION_TOUCH,
                            "write rule " + r.path() + " opens warrantd's own state (" + dir + ", §16 self-protection)"));
                    break;
                }
            }
        }
    }

    /**
     * agent/internal/policy.DefaultDenyWrite 와 같은 목록이다 — <b>한쪽을 고치면 다른 쪽도 고친다.</b>
     * {@code /var/run} 은 Ubuntu 에서 {@code /run} 의 심볼릭 링크다. warrantd 는 경로를 stat 해서
     * inode 로 컴파일하므로 {@code /var/run/warrantd} ALLOW 도 같은 디렉터리를 연다.
     */
    static final List<String> SELF_PROTECTED_DIRS = List.of(
            "/var/lib/warrantd",
            "/run/warrantd",
            "/var/run/warrantd",
            "/etc/warrantd");

    // ── EXEC_WRITE_COMBO (ERROR) ─────────────────────────────────────────────────

    /**
     * 실행 파일 이름 → 같이 열리면 임의 코드 실행이 되는 쓰기 경로.
     * 둘 다 열리면 세션 밖(PID 1 · crond · atd · dockerd)에서, 또는 영장 밖 권한(sudo · mount)으로 임의 코드가 돈다 —
     * 영장 표식이 따라가지 못하는 길이다(docs/flows.md 「표식 전파」 표의 마지막 줄). 실행만 열리면 할 수 있는 일이
     * 정해진 유닛 · 작업뿐이고, 쓰기만 열리면 데몬에게 다시 읽으라고 시킬 수 없다(재부팅 · 다음 주기까지는).
     *
     * <p><b>agent/internal/policy.comboRules 와 같은 짝이다 — 한쪽을 고치면 다른 쪽도 고친다.</b>
     * 노드는 같은 조합을 경고로만 남기고, 서버가 등록 · 신청 때 ERROR 로 막는다. 서버 쪽은 디렉터리를 한 단계
     * 넓게 잡고({@code /etc/systemd} 등) docker · cron · at 짝을 더 갖는다. {@code /var/run/…} 은 {@code /run/…} 의
     * 심볼릭 링크라 둘 다 적는다.
     */
    static final Map<String, List<String>> COMBO_TARGETS = Map.of(
            "systemctl", List.of("/etc/systemd", "/run/systemd", "/var/run/systemd", "/lib/systemd", "/usr/lib/systemd"),
            "systemd-run", List.of("/etc/systemd", "/run/systemd", "/var/run/systemd", "/lib/systemd", "/usr/lib/systemd"),
            "docker", List.of("/etc/docker", "/var/lib/docker", "/run/docker.sock", "/var/run/docker.sock"),
            "crontab", List.of("/var/spool/cron", "/etc/crontab", "/etc/cron.d", "/etc/cron.hourly",
                    "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"),
            "at", List.of("/var/spool/cron", "/var/spool/at"),
            "sudo", List.of("/etc/sudoers", "/etc/sudoers.d"),
            "mount", List.of("/etc/fstab"),
            "umount", List.of("/etc/fstab"));

    private static void execWriteCombo(Policy policy, List<PolicyLintFinding> out) {
        Collection<WriteRule> writes = policy.getWriteRules();
        for (ExecRule e : policy.getExecRules()) {
            for (String target : COMBO_TARGETS.getOrDefault(basename(e.path()), List.of())) {
                if (opensWriteUnder(writes, target)) {
                    out.add(new PolicyLintFinding(Severity.ERROR, EXEC_WRITE_COMBO,
                            "exec " + e.path() + " together with write access to " + target
                                    + " turns the two rules into arbitrary code execution outside the warrant (§04)"));
                }
            }
        }
    }

    // ── RISKY_WRITE · EXEC_IN_WRITABLE_DIR (WARN) ────────────────────────────────

    /**
     * 실행 허용과 무관하게 위험한 쓰기 — 다른 주체(cron · 로그인 셸 · 동적 로더)가 대신 실행해 준다.
     * <b>agent/internal/policy.alwaysRisky 와 같은 목록이다.</b>
     */
    static final Map<String, String> RISKY_WRITES = Map.ofEntries(
            Map.entry("/etc/ld.so.preload", "dynamic loader config — code lands in every later process"),
            Map.entry("/etc/ld.so.conf", "dynamic loader config — code lands in every later process"),
            Map.entry("/etc/ld.so.conf.d", "dynamic loader config — code lands in every later process"),
            Map.entry("/etc/cron.d", "cron runs it on the next tick, no exec rule needed"),
            Map.entry("/etc/crontab", "cron runs it on the next tick, no exec rule needed"),
            Map.entry("/var/spool/cron", "cron runs it on the next tick, no exec rule needed"),
            Map.entry("/etc/cron.hourly", "cron runs it on the next tick, no exec rule needed"),
            Map.entry("/etc/cron.daily", "cron runs it on the next tick, no exec rule needed"),
            Map.entry("/etc/profile", "the next login shell runs it"),
            Map.entry("/etc/profile.d", "the next login shell runs it"),
            Map.entry("/etc/bash.bashrc", "the next login shell runs it"),
            Map.entry("/etc/passwd", "can add accounts or change passwords"),
            Map.entry("/etc/shadow", "can add accounts or change passwords"),
            Map.entry("/etc/group", "can add accounts or change passwords"),
            Map.entry("/root/.ssh", "an authorized_keys entry is a way back in outside any warrant"),
            Map.entry("/etc/ssh", "an authorized_keys entry is a way back in outside any warrant"));

    private static void riskyWrites(Policy policy, List<PolicyLintFinding> out) {
        Collection<WriteRule> writes = policy.getWriteRules();
        RISKY_WRITES.entrySet().stream().sorted(Map.Entry.comparingByKey()).forEach(e -> {
            if (opensWriteUnder(writes, e.getKey())) {
                out.add(new PolicyLintFinding(Severity.WARN, RISKY_WRITE,
                        "write access to " + e.getKey() + " — " + e.getValue()));
            }
        });
        // 실행 허용된 바이너리를 쓸 수 있으면 갈아치워 실행 허용을 다른 내용에 물려줄 수 있다 —
        // ext4 는 지운 inode 번호를 바로 재사용한다(S4). agent 의 같은 검사와 짝이다.
        for (ExecRule e : policy.getExecRules()) {
            if (writable(writes, normalize(e.path()))) {
                out.add(new PolicyLintFinding(Severity.WARN, EXEC_IN_WRITABLE_DIR,
                        "exec " + e.path() + " sits where the policy allows writes — replacing the file passes the exec rule to new content"));
            }
        }
    }

    /**
     * {@code target} 또는 그 아래 어딘가에 파일을 쓸 수 있는가. 판정은 노드와 같다:
     * <b>최장 일치 → 길이가 같으면 DENY → 안 걸리면 금지</b>, {@code recursive} 가 아니면 직계 자식까지만.
     */
    static boolean opensWriteUnder(Collection<WriteRule> writes, String target) {
        String t = normalize(target);
        // 후보 1: target 자신(파일 /etc/crontab 이면 이것), 바로 아래의 아무 이름, 그 한 칸 더 아래.
        // 손자는 target 에 건 DENY 가 recursive 가 아닐 때 위쪽 recursive ALLOW 로 열리는 길이다.
        // 이름에 NUL 을 넣어 어떤 규칙 경로와도 우연히 같아지지 않게 한다.
        List<String> probes = new ArrayList<>(List.of(t, t + "/\0probe", t + "/\0dir/\0probe"));
        // 후보 2: target 아래를 직접 연 ALLOW 규칙 — 그 디렉터리의 자식과 그 경로 자신.
        for (WriteRule r : writes) {
            String p = normalize(r.path());
            if (r.effect() == WriteRule.Effect.ALLOW && within(p, t)) {
                probes.add(p + "/\0probe");
                probes.add(p);
            }
        }
        return probes.stream().anyMatch(probe -> writable(writes, probe));
    }

    /** 경로 {@code file} 에 쓰기가 허용되는가 — 노드의 판정을 문자열로 흉내 낸다. */
    static boolean writable(Collection<WriteRule> writes, String file) {
        String parent = parent(file);
        WriteRule best = null;
        int bestLen = -1;
        for (WriteRule r : writes) {
            String p = normalize(r.path());
            boolean matches = p.equals(file)                                // 그 경로 자신에 건 규칙
                    || p.equals(parent)                                     // 직계 부모 디렉터리
                    || (r.recursive() && within(file, p) && !p.equals(file)); // 조상, recursive
            if (!matches) {
                continue;
            }
            int len = p.length();
            if (len > bestLen || (len == bestLen && r.effect() == WriteRule.Effect.DENY)) {
                best = r;
                bestLen = len;
            }
        }
        return best != null && best.effect() == WriteRule.Effect.ALLOW;
    }

    // ── NET_WIDE_OPEN (WARN) ─────────────────────────────────────────────────────

    private static void netWideOpen(Policy policy, List<PolicyLintFinding> out) {
        for (NetRule n : policy.getNetRules()) {
            if (n.isWideOpen()) {
                out.add(new PolicyLintFinding(Severity.WARN, NET_WIDE_OPEN,
                        "net rule " + n.cidr() + (n.port() == 0 ? "" : " port " + n.port())
                                + " allows outbound to anywhere — reads are not controlled, so this is the exfiltration path (§15)"));
            }
        }
    }

    // ── SCOPE_TOO_WIDE (WARN) ────────────────────────────────────────────────────

    /** 셸 · 인터프리터. 실행 허용에 들어가면 exec 없이 프로세스 안에서 무엇이든 한다 — 실행 화이트리스트가 의미를 잃는다. */
    static final Set<String> SHELLS = Set.of("sh", "bash", "dash", "zsh", "ksh", "mksh", "fish", "csh", "tcsh",
            "busybox", "env");
    private static final Pattern INTERPRETER = Pattern.compile("(python|perl|ruby|php|lua|node|nodejs|tclsh|pwsh)[0-9.]*");

    private static void scopeTooWide(Policy policy, List<PolicyLintFinding> out) {
        for (ExecRule e : policy.getExecRules()) {
            String name = basename(e.path());
            if (SHELLS.contains(name) || INTERPRETER.matcher(name).matches()) {
                out.add(new PolicyLintFinding(Severity.WARN, SCOPE_TOO_WIDE,
                        "exec " + e.path() + " is a shell or interpreter — it can run anything without exec, "
                                + "so the exec allowlist no longer limits what the session does"));
            }
        }
    }

    // ── 경로 문자열 ──────────────────────────────────────────────────────────────

    // "/etc//warrantd/", "/etc/./warrantd" 같은 표기로 비켜 가지 못하게 한다. 경로는 노드의 것이라
    // 서버 파일 시스템을 보지 않고 문자열로만 정리한다.
    private static String normalize(String path) {
        String p = java.nio.file.Path.of(path).normalize().toString();
        return p.length() > 1 && p.endsWith("/") ? p.substring(0, p.length() - 1) : p;
    }

    /** {@code path} 가 {@code dir} 자신이거나 그 아래인가. "/" 는 모든 경로를 덮는다. */
    private static boolean within(String path, String dir) {
        return path.equals(dir) || dir.equals("/") || path.startsWith(dir + "/");
    }

    private static String parent(String path) {
        int i = path.lastIndexOf('/');
        return i <= 0 ? "/" : path.substring(0, i);
    }

    private static String basename(String path) {
        return path.substring(path.lastIndexOf('/') + 1);
    }
}
