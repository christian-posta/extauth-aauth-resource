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

	pb "aauth-service/gen/proto"
	"aauth-service/internal/config"
	"aauth-service/internal/extauthz"
	"aauth-service/internal/httpapi"
	"aauth-service/internal/jwksfetch"
	"aauth-service/internal/policy"
	"aauth-service/internal/resource"
)

var (
	port = flag.Int("port", 0, "Deprecated: override the gRPC listen port")
)

func main() {
	flag.Parse()

	// Load configuration
	cfgPath := os.Getenv("AAUTH_CONFIG")
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	if cfgPath == "" {
		log.Printf("AAUTH_CONFIG is not set; using default in-memory configuration")
	} else {
		log.Printf("Loaded configuration from %s", cfgPath)
	}

	grpcAddr := cfg.Listen.GRPC
	if grpcAddr == "" {
		if cfg.Port != 0 {
			grpcAddr = net.JoinHostPort("", fmt.Sprintf("%d", cfg.Port))
		} else {
			grpcAddr = ":7070"
		}
	}
	if *port != 0 {
		grpcAddr = net.JoinHostPort("", fmt.Sprintf("%d", *port))
	}

	lis, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer()

	// Start HTTP Server
	httpAddr := cfg.Listen.HTTP
	if httpAddr == "" {
		httpAddr = ":8080"
	}

	reg, err := resource.NewRegistry(cfg)
	if err != nil {
		log.Fatalf("Failed to create registry: %v", err)
	}
	for _, rc := range cfg.Resources {
		log.Printf("Configured resource id=%q issuer=%q hosts=%v", rc.ID, rc.Issuer, rc.Hosts)
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

	log.Printf("Policy Engine starting on %s", grpcAddr)
	log.Printf("This service implements the Envoy ext_authz protocol")
	log.Printf("Configure AgentGateway to use: ext_authz: { target: '%s' }", lis.Addr().String())

	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
