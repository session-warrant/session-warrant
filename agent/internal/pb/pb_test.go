package pb_test

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"

	"github.com/session-warrant/session-warrant/agent/internal/pb"
)

func unwarranted() *pb.AuditEvent {
	return &pb.AuditEvent{
		NodeSeq: 7,
		Hook:    pb.Hook_HOOK_AGENT,
		Origin:  pb.Origin_ORIGIN_AGENT,
		Payload: &pb.AuditEvent_UnwarrantedSession{UnwarrantedSession: &pb.UnwarrantedSessionEvent{
			LoginAccount:  "ec2-user",
			SourceAddress: "10.0.0.5",
			CgroupId:      7594,
			SessionId:     "c1",
			Reason:        pb.UnwarrantedSessionEvent_REASON_NO_KEY,
		}},
	}
}

func TestAuditEventOneofRoundTrip(t *testing.T) {
	in := unwarranted()
	b, err := proto.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	out := &pb.AuditEvent{}
	if err := proto.Unmarshal(b, out); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(in, out) {
		t.Fatalf("round trip mismatch:\n in=%v\nout=%v", in, out)
	}
	if out.GetUnwarrantedSession().GetReason() != pb.UnwarrantedSessionEvent_REASON_NO_KEY {
		t.Fatalf("oneof payload lost: %v", out.GetPayload())
	}
}

// Fake server: acks the last node_seq of each batch.
type ackServer struct {
	pb.UnimplementedAuditIngestServiceServer
	got []*pb.AuditBatch
}

func (s *ackServer) Stream(st grpc.BidiStreamingServer[pb.AuditBatch, pb.AuditAck]) error {
	for {
		b, err := st.Recv()
		if err != nil {
			return nil
		}
		s.got = append(s.got, b)
		if err := st.Send(&pb.AuditAck{SeqEpoch: b.SeqEpoch, AckedThroughNodeSeq: b.LastNodeSeq}); err != nil {
			return err
		}
	}
}

func TestAuditIngestStreamOverBufconn(t *testing.T) {
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	fake := &ackServer{}
	pb.RegisterAuditIngestServiceServer(srv, fake)
	go srv.Serve(lis)
	defer srv.Stop()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	st, err := pb.NewAuditIngestServiceClient(conn).Stream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Send(&pb.AuditBatch{Events: []*pb.AuditEvent{unwarranted()}, LastNodeSeq: 7, SeqEpoch: 42}); err != nil {
		t.Fatal(err)
	}
	ack, err := st.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if ack.GetSeqEpoch() != 42 || ack.GetAckedThroughNodeSeq() != 7 {
		t.Fatalf("ack = %v, want epoch 42 through 7", ack)
	}
	st.CloseSend()
	if len(fake.got) != 1 || fake.got[0].GetEvents()[0].GetUnwarrantedSession().GetLoginAccount() != "ec2-user" {
		t.Fatalf("server got %v", fake.got)
	}
}
