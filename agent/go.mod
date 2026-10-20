module github.com/session-warrant/session-warrant/agent

go 1.25.0

require (
	github.com/cilium/ebpf v0.22.0
	golang.org/x/crypto v0.55.0
	golang.org/x/sys v0.47.0
	google.golang.org/grpc v1.81.0
	google.golang.org/protobuf v1.36.12
)

require (
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260226221140-a57be14db171 // indirect
	google.golang.org/grpc/cmd/protoc-gen-go-grpc v1.6.2 // indirect
)

tool (
	google.golang.org/grpc/cmd/protoc-gen-go-grpc
	google.golang.org/protobuf/cmd/protoc-gen-go
)
