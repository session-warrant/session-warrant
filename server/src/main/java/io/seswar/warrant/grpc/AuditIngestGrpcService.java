package io.seswar.warrant.grpc;

import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import io.seswar.warrant.application.AuditIngestService;
import io.seswar.warrant.application.NodeRegistry;
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

    // Until mTLS lands the identity is the reported hostname; "dev:" marks it as local-only.
    private static final String DEV_IDENTITY_PREFIX = "dev:";

    private final AuditIngestService auditIngestService;
    private final NodeRegistry nodeRegistry;

    @Override
    public StreamObserver<AuditBatch> stream(StreamObserver<AuditAck> ack) {
        return new IngestStream(ack);
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
            } catch (IllegalArgumentException e) {
                fail(Status.INVALID_ARGUMENT, e);
            }
        }

        @Override
        public void onError(Throwable t) {

        }

        @Override
        public void onCompleted() {
            if(!closed) {
                closed = true;
                ack.onCompleted();
            }
        }


        private void identify(AuditBatch batch) {
            long epoch = batch.getSeqEpoch();
            if (batch.hasNode()) {
                NodeRegistry.Report report = AuditProtoMapper.toReport(batch.getNode(), epoch);
                if (identity == null) {
                    identity = DEV_IDENTITY_PREFIX + report.hostname();
                }
                nodeId = nodeRegistry.register(identity, report).nodeId();
            } else if (nodeId == null) {
                throw new IllegalArgumentException("first batch without NodeHello");
            } else if (epoch != seqEpoch) {
                throw new IllegalArgumentException("seq_epoch changed mid-stream without NodeHello: "
                        + seqEpoch + " -> " + epoch);
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
