package io.seswar.warrant.warrant.push;

import io.grpc.stub.StreamObserver;
import io.seswar.warrant.proto.AgentProtos.PushMessage;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArraySet;

/**
 * 노드별 열린 push 스트림 보관. 키는 노드가 자기 신고한 hostname 이다 — mTLS 전까지의 임시 신원이고,
 * 영장의 {@code target_hosts} 와 같은 이름이다.
 *
 * <p>프로세스 로컬 상태다. 서버를 여러 대로 늘리면 노드가 붙은 인스턴스에서만 push 가 되므로,
 * 그때는 브로드캐스트(예: PostgreSQL LISTEN/NOTIFY)를 앞에 둔다.
 * <b>지금 단계에서 그걸 미리 넣지 않는다</b> — 데모 규모는 단일 인스턴스로 충분하다.
 */
@Slf4j
@Component
public class NodeStreamRegistry {

    private final Map<String, Set<StreamObserver<PushMessage>>> streams = new ConcurrentHashMap<>();

    public void attach(String hostname, StreamObserver<PushMessage> stream) {
        streams.computeIfAbsent(hostname, h -> new CopyOnWriteArraySet<>()).add(stream);
    }

    public void detach(String hostname, StreamObserver<PushMessage> stream) {
        Set<StreamObserver<PushMessage>> set = streams.get(hostname);
        if (set != null) {
            set.remove(stream);
        }
    }

    /** @return 받은 스트림 수. 0 이면 그 노드는 지금 안 붙어 있다 — 재연결 때 활성 집합으로 따라잡는다 */
    public int send(String hostname, PushMessage message) {
        int sent = 0;
        for (StreamObserver<PushMessage> s : streams.getOrDefault(hostname, Set.of())) {
            try {
                // One gRPC stream must not be written from two threads at once.
                synchronized (s) {
                    s.onNext(message);
                }
                sent++;
            } catch (RuntimeException e) {
                log.warn("push to {} failed, dropping the stream: {}", hostname, e.toString());
                detach(hostname, s);
            }
        }
        return sent;
    }
}
