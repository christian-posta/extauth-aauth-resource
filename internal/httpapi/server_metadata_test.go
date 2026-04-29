package httpapi_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"aauth-service/internal/config"
	"aauth-service/internal/httpapi"
	"aauth-service/internal/jwksfetch"
	"aauth-service/internal/policy"
	"aauth-service/internal/resource"
)

func TestMetadataAuthorizationEndpointDefault(t *testing.T) {
	cfg := &config.Config{
		Resources: []config.ResourceConfigYAML{
			{
				ID:              "res-meta",
				Issuer:          "https://res.example.com",
				Hosts:           []string{"res.example.com"},
				SignatureWindow: time.Minute,
			},
		},
	}
	reg, err := resource.NewRegistry(cfg)
	if err != nil {
		t.Fatal(err)
	}

	srv := httpapi.NewServer(reg, jwksfetch.NewMockClient(), policy.NewDefaultEngine())
	req := httptest.NewRequest(http.MethodGet, "https://res.example.com/.well-known/aauth-resource.json", nil)
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("got %d want %d", rr.Code, http.StatusOK)
	}

	var metadata map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&metadata); err != nil {
		t.Fatal(err)
	}
	if metadata["authorization_endpoint"] != "https://res.example.com/resource/token" {
		t.Fatalf("authorization_endpoint=%v", metadata["authorization_endpoint"])
	}
	if _, ok := metadata["resource_token_endpoint"]; ok {
		t.Fatal("resource_token_endpoint should be absent")
	}
}

func TestMetadataAuthorizationEndpointOverride(t *testing.T) {
	cfg := &config.Config{
		Resources: []config.ResourceConfigYAML{
			{
				ID:                            "res-meta",
				Issuer:                        "https://res.example.com",
				Hosts:                         []string{"res.example.com"},
				SignatureWindow:               time.Minute,
				AuthorizationEndpointOverride: "https://public.example.com/custom/token",
			},
		},
	}
	reg, err := resource.NewRegistry(cfg)
	if err != nil {
		t.Fatal(err)
	}

	srv := httpapi.NewServer(reg, jwksfetch.NewMockClient(), policy.NewDefaultEngine())
	req := httptest.NewRequest(http.MethodGet, "https://res.example.com/.well-known/aauth-resource.json", nil)
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	var metadata map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&metadata); err != nil {
		t.Fatal(err)
	}
	if metadata["authorization_endpoint"] != "https://public.example.com/custom/token" {
		t.Fatalf("authorization_endpoint=%v", metadata["authorization_endpoint"])
	}
}

func TestJWKSIncludesAllResourceKeysForSharedIssuer(t *testing.T) {
	_, spaPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, maaPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		Resources: []config.ResourceConfigYAML{
			{
				ID:              "supply-chain-agent",
				Issuer:          "http://localhost:8081",
				Hosts:           []string{"localhost:8081"},
				SigningKey:      config.SigningKeyYAML{Kid: "spa-rsk-1"},
				SignatureWindow: time.Minute,
			},
			{
				ID:              "market-analysis-agent",
				Issuer:          "http://localhost:8081",
				Hosts:           []string{"market-analysis-agent.localhost:8081"},
				SigningKey:      config.SigningKeyYAML{Kid: "maa-rsk-1"},
				SignatureWindow: time.Minute,
			},
		},
	}
	reg, err := resource.NewRegistry(cfg)
	if err != nil {
		t.Fatal(err)
	}
	spa, _ := reg.ByID("supply-chain-agent")
	spa.PrivateKey = spaPriv
	maa, _ := reg.ByID("market-analysis-agent")
	maa.PrivateKey = maaPriv

	srv := httpapi.NewServer(reg, jwksfetch.NewMockClient(), policy.NewDefaultEngine())
	req := httptest.NewRequest(http.MethodGet, "http://localhost:8081/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("got %d want %d body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}

	var jwks struct {
		Keys []map[string]interface{} `json:"keys"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&jwks); err != nil {
		t.Fatal(err)
	}

	kids := map[string]bool{}
	for _, key := range jwks.Keys {
		kid, _ := key["kid"].(string)
		x, _ := key["x"].(string)
		if x == "" {
			t.Fatalf("key %q is missing x coordinate", kid)
		}
		kids[kid] = true
	}
	for _, kid := range []string{"spa-rsk-1", "maa-rsk-1"} {
		if !kids[kid] {
			t.Fatalf("JWKS missing kid %q: %#v", kid, jwks.Keys)
		}
	}
}
