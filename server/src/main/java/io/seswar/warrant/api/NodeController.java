package io.seswar.warrant.api;

// @RestController @RequestMapping("/api/nodes")
public class NodeController {

    // GET /api/nodes            — 커널 버전 · bpfLsmEnabled · 마지막 하트비트
    // GET /api/nodes/{id}

    /**
     * 목록에서 {@code bpfLsmEnabled=false} 노드를 눈에 띄게 표시한다.
     * 그 노드에는 ENFORCE 영장을 발급해도 강제되지 않는다 —
     * 이 사실이 화면에 안 보이면 "통제되고 있다"는 잘못된 믿음이 생긴다.
     */
    public Object list() {
        throw new UnsupportedOperationException("미구현");
    }
}
