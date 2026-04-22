package httpapi

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"policy_engine/internal/config"
	"policy_engine/internal/policy"
	"policy_engine/internal/resource"
)

type Server struct {
	registry     *resource.Registry
	jwksClient   jwksFetcher
	policyEngine policy.Engine
}

type jwksFetcher interface {
	Get(ctx context.Context, uri string) (jwk.Set, error)
	GetMetadata(ctx context.Context, uri string) (map[string]interface{}, error)
	Invalidate(uri string)
}

func NewServer(registry *resource.Registry, jwksClient jwksFetcher, engine policy.Engine) *Server {
	return &Server{
		registry:     registry,
		jwksClient:   jwksClient,
		policyEngine: engine,
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/metrics":
		s.handleMetrics(w, r)
		return
	}

	rc, ok := s.registry.ByHost(r.Host)
	if !ok {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	switch r.URL.Path {
	case "/.well-known/aauth-resource.json":
		s.handleMetadata(w, r, rc)
	case "/.well-known/jwks.json":
		s.handleJWKS(w, r, rc)
	case "/resource/token":
		s.handleResourceToken(w, r, rc)
	default:
		http.Error(w, "Not Found", http.StatusNotFound)
	}
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	promhttp.Handler().ServeHTTP(w, r)
}

func (s *Server) handleMetadata(w http.ResponseWriter, r *http.Request, rc *config.ResourceConfig) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	metadata := map[string]interface{}{
		"issuer":                          rc.Issuer,
		"jwks_uri":                        rc.Issuer + "/.well-known/jwks.json", // Could be from config but usually derived
		"authorization_endpoint":          rc.AuthorizationEndpoint,
		"resource_token_endpoint":         rc.Issuer + "/resource/token",
		"supported_scopes":                rc.SupportedScopes,
		"scope_descriptions":              rc.ScopeDescriptions,
		"additional_signature_components": rc.AdditionalSignatureComponents,
		"signature_window":                int(rc.SignatureWindow.Seconds()),
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	json.NewEncoder(w).Encode(metadata)
}

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request, rc *config.ResourceConfig) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	keyEntry := map[string]interface{}{
		"kty": "OKP",
		"crv": "Ed25519",
		"kid": rc.SigningKey.Kid,
		"alg": "EdDSA",
		"use": "sig",
	}

	if rc.PrivateKey != nil {
		pubKey := rc.PrivateKey.Public().(ed25519.PublicKey)
		keyEntry["x"] = base64.RawURLEncoding.EncodeToString(pubKey)
	}

	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{keyEntry},
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	json.NewEncoder(w).Encode(jwks)
}

func Start(listenAddr string, registry *resource.Registry, jwksClient jwksFetcher, engine policy.Engine) {
	srv := NewServer(registry, jwksClient, engine)

	go func() {
		log.Printf("Starting HTTP API on %s", listenAddr)
		if err := http.ListenAndServe(listenAddr, srv); err != nil {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()
}
