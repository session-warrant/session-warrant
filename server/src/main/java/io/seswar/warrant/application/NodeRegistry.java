package io.seswar.warrant.application;

import io.seswar.warrant.domain.node.Node;

import java.util.UUID;

// @Service
public class NodeRegistry {

    /** warrantd 최초 접속 시 등록. bpfLsmEnabled 의 의미는 {@link Node} 참조. */
    public Node register(String hostname, String kernelVersion, boolean bpfLsmEnabled) {
        throw new UnsupportedOperationException("미구현");
    }

    public void heartbeat(UUID nodeId) {
        throw new UnsupportedOperationException("미구현");
    }

    /**
     * 하트비트가 끊긴 노드. 여기서 "노드가 죽었다"고 단정하면 안 된다. warrantd 가 죽어도 BPF 는 pin 되어 있어
     * 강제는 계속되고 만료 · 취소도 맵에 이미 있는 값대로 작동한다(§17).
     * 끊긴 것은 <b>감사 이벤트 수집과 신규 영장 전달</b>이지 집행이 아니다.
     */
    public java.util.List<Node> staleNodes(java.time.Duration threshold) {
        throw new UnsupportedOperationException("미구현");
    }
}
