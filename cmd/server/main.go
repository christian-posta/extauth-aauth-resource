package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"google.golang.org/grpc"

	pb "policy_engine/gen/proto"
	"policy_engine/internal/config"
	"policy_engine/internal/extauthz"
	"policy_engine/internal/httpapi"
	"policy_engine/internal/jwksfetch"
	"policy_engine/internal/policy"
	"policy_engine/internal/resource"
)

var (
	port = flag.Int("port", 7070, "The server port")
)

func main() {
	flag.Parse()

	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Use the port from flag if provided, otherwise use config default
	if *port != 0 {
		cfg.Port = *port
	} else if cfg.Port == 0 {
		cfg.Port = 7070
	}

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer()

	// Start HTTP Server
	httpAddr := ":8080"

	reg, err := resource.NewRegistry(cfg)
	if err != nil {
		log.Fatalf("Failed to create registry: %v", err)
	}

	engine := policy.NewDefaultEngine()
	jwksClient := jwksfetch.NewClient(cfg)

	httpapi.Start(httpAddr, reg, jwksClient, engine)

	// Register the AAuth / Legacy hybrid handler
	handler, err := extauthz.NewHandlerWithRegistry(cfg, reg)
	if err != nil {
		log.Fatalf("failed to create handler: %v", err)
	}
	pb.RegisterAuthorizationServer(s, handler)

	// Hot reload logic
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP)
	go func() {
		for range sigCh {
			log.Println("Received SIGHUP: hot reload not yet implemented")
			// Future work: dynamically update the registry and restart the servers if necessary
		}
	}()

	log.Printf("Policy Engine starting on port %d", cfg.Port)
	log.Printf("This service implements the Envoy ext_authz protocol")
	log.Printf("Configure AgentGateway to use: ext_authz: { target: 'localhost:%d' }", cfg.Port)

	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
