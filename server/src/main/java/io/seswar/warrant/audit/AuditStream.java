package io.seswar.warrant.audit;

import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter.SseEventBuilder;

import java.io.IOException;
import java.time.Duration;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

/**
 * 대시보드에 "새 기록 있음"만 알린다. 기록 자체는 싣지 않는다 — 화면은 알림을 받으면
 * {@code GET /api/audit/events?after=} 로 가져온다. 끊겼다 다시 붙을 때도 같은 조회 한 번이면 되므로
 * 놓친 알림이 기록 유실이 되지 않는다.
 *
 * <p>서버 한 대 안에서만 퍼진다. 여러 대가 되면 PostgreSQL LISTEN/NOTIFY 를 붙인다.
 */
@Slf4j
@Component
public class AuditStream {

    // EventSource reconnects by itself, so a finite timeout only recycles the connection.
    static final Duration TIMEOUT = Duration.ofMinutes(30);
    // Below common proxy idle timeouts (60s); also how a vanished browser is noticed and dropped.
    static final Duration HEARTBEAT = Duration.ofSeconds(25);

    private final Set<SseEmitter> emitters = ConcurrentHashMap.newKeySet();
    // One virtual thread per send: a stalled browser must not hold up the ingest thread or the other browsers.
    private final ExecutorService sender = Executors.newVirtualThreadPerTaskExecutor();
    private final ScheduledExecutorService heartbeat = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "audit-stream-heartbeat");
        t.setDaemon(true);
        return t;
    });

    AuditStream() {
        long every = HEARTBEAT.toMillis();
        heartbeat.scheduleAtFixedRate(() -> broadcast(() -> SseEmitter.event().comment("")), every, every, TimeUnit.MILLISECONDS);
    }

    // Called by AuditQueryController.stream. The first event commits the response so the browser sees "open".
    SseEmitter subscribe() {
        SseEmitter e = new SseEmitter(TIMEOUT.toMillis());
        emitters.add(e);
        e.onCompletion(() -> emitters.remove(e));
        e.onTimeout(e::complete);
        e.onError(t -> emitters.remove(e));
        send(e, SseEmitter.event().name("ready").data(""));
        return e;
    }

    // Called by Spring after AuditIngestService.ingest commits, so a browser that fetches at once sees the rows.
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    void ingested(AuditIngestService.Result r) {
        broadcast(() -> SseEmitter.event().name("audit").data(r, MediaType.APPLICATION_JSON));
    }

    // A builder is consumed by send (build() appends to it), so every subscriber gets its own.
    private void broadcast(Supplier<SseEventBuilder> event) {
        for (SseEmitter e : emitters) {
            sender.execute(() -> send(e, event.get()));
        }
    }

    private void send(SseEmitter e, SseEventBuilder event) {
        try {
            e.send(event);
        } catch (IOException | IllegalStateException gone) {
            // The container sees the broken connection too and fires onError; only stop sending here.
            emitters.remove(e);
            log.debug("audit stream: dropped a subscriber: {}", gone.toString());
        }
    }

    @PreDestroy
    void close() {
        heartbeat.shutdownNow();
        emitters.forEach(SseEmitter::complete);
        sender.shutdown();
    }
}
