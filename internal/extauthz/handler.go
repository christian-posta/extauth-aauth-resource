package extauthz

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"log"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "aauth-service/gen/proto"
	"aauth-service/internal/config"
	"aauth-service/internal/jwksfetch"
	"aauth-service/internal/policy"
	"aauth-service/internal/resource"
)

type Handler struct {
	pb.UnimplementedAuthorizationServer
	registry *resource.Registry
	aauth    *AAuthHandler
}

func NewHandler(cfg *config.Config) (*Handler, error) {
	reg, err := resource.NewRegistry(cfg)
	if err != nil {
		return nil, err
	}

	return NewHandlerWithRegistry(cfg, reg)
}

func NewHandlerWithRegistry(cfg *config.Config, reg *resource.Registry) (*Handler, error) {
	engine := policy.NewDefaultEngine()
	jwksClient := jwksfetch.NewClient(cfg)

	return &Handler{
		registry: reg,
		aauth:    NewAAuthHandler(engine, jwksClient),
	}, nil
}

func (h *Handler) Check(ctx context.Context, req *pb.CheckRequest) (*pb.CheckResponse, error) {
	attrs := req.GetAttributes()
	if attrs == nil {
		return nil, status.Error(codes.InvalidArgument, "missing attributes")
	}

	exts := attrs.GetContextExtensions()
	resID, hasExt := exts["aauth_resource_id"]

	var rc *config.ResourceConfig
	var ok bool

	if hasExt {
		rc, ok = h.registry.ByID(resID)
		if !ok {
			log.Printf("Unknown aauth_resource_id: %s", resID)
			return h.deny()
		}
	} else {
		// Fallback to authority from headers / http.host (see AuthorityForSignature).
		host := AuthorityForSignature(attrs.GetRequest().GetHttp())
		rc, ok = h.registry.ByHost(host)
		if !ok {
			log.Printf("Non-AAuth route (host: %s), allowing by default", host)
			// Non-AAuth routes: allow by default
			return h.allow()
		}
		log.Printf("Matched host %s to resource %s", host, rc.ID)
	}

	return h.aauth.Check(ctx, req, rc)
}

func (h *Handler) allow() (*pb.CheckResponse, error) {
	return &pb.CheckResponse{
		Status: &pb.Status{Code: 0},
		HttpResponse: &pb.CheckResponse_OkResponse{
			OkResponse: &pb.OkHttpResponse{},
		},
	}, nil
}

func (h *Handler) deny() (*pb.CheckResponse, error) {
	return &pb.CheckResponse{
		Status: &pb.Status{Code: 7}, // PERMISSION_DENIED
		HttpResponse: &pb.CheckResponse_DeniedResponse{
			DeniedResponse: &pb.DeniedHttpResponse{
				Status: &pb.HttpStatus{Code: pb.StatusCode_Forbidden},
			},
		},
	}, nil
}

// InjectTestKey is a hack for tests to inject an ed25519 private key since we mock the config
func (h *Handler) InjectTestKey(id string, priv crypto.PrivateKey) {
	rc, ok := h.registry.ByID(id)
	if ok {
		if edPriv, ok := priv.(crypto.PrivateKey); ok {
			rc.PrivateKey = edPriv.(ed25519.PrivateKey)
		}
	}
}
