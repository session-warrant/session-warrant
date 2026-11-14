package io.seswar.warrant.audit;

import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import io.seswar.warrant.audit.AuditIngestService;
import io.seswar.warrant.node.NodePeer;
import io.seswar.warrant.node.NodeRegistry;
import io.seswar.warrant.proto.AgentProtos.AuditAck;
import io.seswar.warrant.proto.AgentProtos.AuditBatch;
import io.seswar.warrant.proto.AuditIngestServiceGrpc;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.UUID;

/**
 * warrantd와 연결된 gRPC 스트림을 읽어서 들어오는 배치를 저장계층에 넘기고, 저장된 만큼 ACK를 보냄
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuditIngestGrpcService extends AuditIngestServiceGrpc.AuditIngestServiceImplBase {

    // Without mTLS (local development) a node is its reported hostname; "dev:" marks it as unverified.
    private static final String DEV_IDENTITY_PREFIX = "dev:";

    private final AuditIngestService auditIngestService;
    private final NodeRegistry nodeRegistry;

    @Override
    public StreamObserver<AuditBatch> stream(StreamObserver<AuditAck> ack) {
        return new IngestStream(ack);
    }

    /** 인증서와 다른 호스트 이름을 댔다. 남의 노드 이름으로 기록을 올리는 길이다. */
    static final class NodeImpersonation extends RuntimeException {
        NodeImpersonation(String message) {
            super(message);
        }
    }

    // With a client certificate the node is that certificate, and must call itself by the certificate's name.
    static String identityOf(String hostname) {
        NodePeer peer = NodePeer.current();
        if (peer == null) {
            return DEV_IDENTITY_PREFIX + hostname;
        }
        if (!hostname.equals(peer.hostname())) {
            throw new NodeImpersonation("certificate is for " + peer.hostname() + ", NodeHello says " + hostname);
        }
        return peer.identity();
    }

    private final class IngestStream implements StreamObserver<AuditBatch> {

        private final StreamObserver<AuditAck> ack;
        private String identity;
        private UUID nodeId;
        private long seqEpoch;
        private boolean closed;

        public IngestStream(StreamObserver<AuditAck> ack) {
            this.ack = ack;
        }

        @Override
        public void onNext(AuditBatch batch) {
            if (closed) {
                return;
            }
            try {
                identify(batch);
                store(batch);
                ackThrough(batch);
            } catch (NodeImpersonation e) {
                fail(Status.PERMISSION_DENIED, e);
            } catch (IllegalArgumentException e) {
                fail(Status.INVALID_ARGUMENT, e);
            }
        }

        // The stream broke (cancel, network, shutdown). Stored batches are committed; warrantd resends the rest.
        @Override
        public void onError(Throwable t) {
            closed = true;
            log.debug("audit stream from node {} ended: {}", nodeId, Status.fromThrowable(t));
        }

        @Override
        public void onCompleted() {
            if(!closed) {
                closed = true;
                ack.onCompleted();
            }
        }


        // The first batch must carry NodeHello. Epoch is fixed for the stream: it only changes when bbolt
        // is recreated, which means a restart and a new stream. 0 means warrantd never set it.
        private void identify(AuditBatch batch) {
            long epoch = batch.getSeqEpoch();
            boolean first = nodeId == null;

            if (epoch == 0) {
                throw new IllegalArgumentException("seq_epoch is 0");
            }
            if (first && !batch.hasNode()) {
                throw new IllegalArgumentException("first batch without NodeHello");
            }
            if (!first && epoch != seqEpoch) {
                throw new IllegalArgumentException("seq_epoch changed mid-stream: " + seqEpoch + " -> " + epoch);
            }
            if (batch.hasNode()) {
                NodeRegistry.Report report = AuditProtoMapper.toReport(batch.getNode(), epoch);
                if (first) {
                    identity = identityOf(report.hostname());
                }
                nodeId = nodeRegistry.register(identity, report).nodeId();
            }
            seqEpoch = epoch;
        }

        private void store(AuditBatch batch) {
            auditIngestService.ingest(nodeId, AuditProtoMapper.toBatch(nodeId, batch));
        }

        // 저장이 끝난 뒤에만 불린다. AuditAck{seq_epoch, acked_through_node_seq = last_node_seq}
        private void ackThrough(AuditBatch batch) {
            ack.onNext(AuditAck.newBuilder()
                    .setSeqEpoch(batch.getSeqEpoch())
                    .setAckedThroughNodeSeq(batch.getLastNodeSeq())
                    .build());
        }

        // ack 없이 스트림을 닫는다. warrantd 는 마지막 ack 다음부터 다시 보낸다
        private void fail(Status status, Exception cause) {
            closed = true;
            log.warn("audit stream from node {} rejected: {}", nodeId, cause.getMessage());
            ack.onError(status.withDescription(cause.getMessage()).withCause(cause).asRuntimeException());
        }

    }
}
