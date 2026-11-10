package io.seswar.warrant.policy;

/**
 * 정책 lint 결과 한 건.
 *
 * @param severity ERROR 면 발급을 막고, WARN 이면 승인자에게 보여준다
 * @param code     예: {@code EXEC_WRITE_COMBO}, {@code DENY_ON_FILE_INODE}, {@code NET_WIDE_OPEN}
 * @param message  사람이 읽는 설명
 */
public record PolicyLintFinding(Severity severity, String code, String message) {

    public enum Severity { WARN, ERROR }
}
