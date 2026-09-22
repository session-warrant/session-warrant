package io.seswar.warrant.domain.policy;

/**
 * 쓰기 허용 한 줄.
 *
 * <p>허용과 금지는 <b>비대칭</b>이다(§15).
 * <ul>
 *   <li>허용 목록은 디렉터리 inode 로 충분하다 — 그 이하 inode 면 통과</li>
 *   <li>금지 목록을 <b>파일</b> inode 로 걸면 뚫린다 — {@code /etc/passwd} 를 막아도
 *       mv 후 재생성하면 새 inode 라 목록 밖이다. 금지는 반드시 <b>디렉터리</b> inode 로 건다</li>
 * </ul>
 * 그래서 금지 대상에는 inode_create · unlink · rename · link · symlink 를 한 세트로 걸어야 완전해진다.
 *
 * <p>판정 순서: <b>최장 일치 → 길이가 같으면 DENY → 안 걸리면 금지.</b> 목록 순서는 무의미하다.
 */
// @Embeddable
public record WriteRule(String path, boolean recursive, Effect effect) {

    /**
     * wire 값은 proto {@code WriteRule.Effect} 와 같다. proto 의 0 = {@code EFFECT_UNSPECIFIED} 는
     * 여기 대응이 없다 — 빠뜨린 DENY 가 ALLOW 로 읽히면 안 되므로 매퍼가 0 을 만나면 예외.
     */
    public enum Effect {
        ALLOW(1),
        DENY(2);

        private final int wireValue;

        Effect(int wireValue) {
            this.wireValue = wireValue;
        }

        public int wireValue() {
            return wireValue;
        }
    }

    /**
     * DENY 인데 경로가 파일을 가리키면 우회 가능한 규칙이다.
     * 정책 lint 에서 거부해야 한다.
     */
    public boolean isUnsafeDenyShape() {
        throw new UnsupportedOperationException("미구현");
    }
}
