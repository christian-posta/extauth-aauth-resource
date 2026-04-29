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

	"aauth-service/internal/config"
	"aauth-service/internal/policy"
	"aauth-service/internal/resource"
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
		"supported_scopes":                rc.SupportedScopes,
		"scope_descriptions":              rc.ScopeDescriptions,
		"additional_signature_components": rc.AdditionalSignatureComponents,
		"signature_window":                int(rc.SignatureWindow.Seconds()),
	}
	if rc.ClientName != "" {
		metadata["client_name"] = rc.ClientName
	}
	if rc.LogoURI != "" {
		metadata["logo_uri"] = rc.LogoURI
	}
	if rc.LogoDarkURI != "" {
		metadata["logo_dark_uri"] = rc.LogoDarkURI
	}
	if rc.LoginEndpoint != "" {
		metadata["login_endpoint"] = rc.LoginEndpoint
	}
	if resourceCanMintTokens(rc) {
		metadata["authorization_endpoint"] = authorizationEndpointForResource(rc)
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

	keyEntries := s.jwksKeysForIssuer(rc)
	jwks := map[string]interface{}{
		"keys": keyEntries,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	json.NewEncoder(w).Encode(jwks)
}

func (s *Server) jwksKeysForIssuer(rc *config.ResourceConfig) []map[string]interface{} {
	resources := s.registry.ByIssuer(rc.Issuer)
	if len(resources) == 0 {
		resources = []*config.ResourceConfig{rc}
	}

	keys := make([]map[string]interface{}, 0, len(resources))
	for _, resourceConfig := range resources {
		keyEntry := map[string]interface{}{
			"kty": "OKP",
			"crv": "Ed25519",
			"kid": resourceConfig.SigningKey.Kid,
			"alg": "EdDSA",
			"use": "sig",
		}

		if resourceConfig.PrivateKey != nil {
			pubKey := resourceConfig.PrivateKey.Public().(ed25519.PublicKey)
			keyEntry["x"] = base64.RawURLEncoding.EncodeToString(pubKey)
		}
		keys = append(keys, keyEntry)
	}
	return keys
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

func authorizationEndpointForResource(rc *config.ResourceConfig) string {
	if rc.AuthorizationEndpointOverride != "" {
		return rc.AuthorizationEndpointOverride
	}
	return rc.Issuer + "/resource/token"
}

func resourceCanMintTokens(rc *config.ResourceConfig) bool {
	return rc != nil && len(rc.PrivateKey) > 0 && rc.SigningKey.Kid != ""
}
