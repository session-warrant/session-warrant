package io.seswar.warrant.node;

/** 폐기된 노드 신원으로 붙었다. gRPC 층은 PERMISSION_DENIED 로 끊는다. */
public class NodeRevokedException extends RuntimeException {

    public NodeRevokedException(String identity) {
        super("node identity " + identity + " is revoked");
    }
}
