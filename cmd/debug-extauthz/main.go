// debug-extauthz: a minimal ext_authz gRPC server that dumps every CheckRequest
// and always returns OK so agentgateway doesn't block requests.
//
// Usage: go run ./cmd/debug-extauthz  (listens on :7071)
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"

	"google.golang.org/grpc"

	pb "policy_engine/gen/proto"
)

type debugServer struct {
	pb.UnimplementedAuthorizationServer
}

func (s *debugServer) Check(ctx context.Context, req *pb.CheckRequest) (*pb.CheckResponse, error) {
	attrs := req.GetAttributes()
	http := attrs.GetRequest().GetHttp()

	fmt.Println("─────────────────────────────────────────")
	fmt.Printf("Method    : %s\n", http.GetMethod())
	fmt.Printf("Host      : %s\n", http.GetHost())
	fmt.Printf("Path      : %s\n", http.GetPath())
	fmt.Println("Headers:")
	for k, v := range http.GetHeaders() {
		fmt.Printf("  %s: %s\n", k, v)
	}
	if exts := attrs.GetContextExtensions(); len(exts) > 0 {
		b, _ := json.Marshal(exts)
		fmt.Printf("ContextExt: %s\n", b)
	}
	fmt.Println("─────────────────────────────────────────")

	return &pb.CheckResponse{
		Status: &pb.Status{Code: 0},
		HttpResponse: &pb.CheckResponse_OkResponse{
			OkResponse: &pb.OkHttpResponse{},
		},
	}, nil
}

func main() {
	lis, err := net.Listen("tcp", ":7071")
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	s := grpc.NewServer()
	pb.RegisterAuthorizationServer(s, &debugServer{})
	log.Println("debug-extauthz listening on :7071 — send requests to agentgateway to inspect")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
