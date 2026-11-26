package io.seswar.warrant.node;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArraySet;

/**
 * 노드별 열린 gRPC 스트림(감사 스트림 · 영장 구독). 노드를 폐기하면 그 신원의 스트림을 전부 끊는다 —
 * 인증서 확인은 연결할 때만 하므로, 끊지 않으면 이미 열린 스트림은 폐기 뒤에도 살아 있다.
 *
 * <p>키는 노드 신원(인증서 지문 · 평문이면 {@code dev:<호스트>}). 프로세스 로컬 상태다 — NodeStreamRegistry 와 같은 한계.
 */
@Slf4j
@Component
public class NodeConnections {

    /** 스트림을 끊는 방법. 스트림마다 다르다(감사: ack 없이 오류, 구독: 오류 + 등록 해제). */
    @FunctionalInterface
    public interface Closer {
        void close(String why);
    }

    private final Map<String, Set<Closer>> open = new ConcurrentHashMap<>();

    public void attach(String identity, Closer closer) {
        open.computeIfAbsent(identity, k -> new CopyOnWriteArraySet<>()).add(closer);
    }

    public void detach(String identity, Closer closer) {
        Set<Closer> set = open.get(identity);
        if (set != null) {
            set.remove(closer);
        }
    }

    /** @return 끊은 스트림 수 */
    public int closeAll(String identity, String why) {
        Set<Closer> set = open.remove(identity);
        if (set == null) {
            return 0;
        }
        int n = 0;
        for (Closer c : set) {
            try {
                c.close(why);
                n++;
            } catch (RuntimeException e) {
                log.warn("closing a stream of {} failed: {}", identity, e.toString());
            }
        }
        return n;
    }
}
