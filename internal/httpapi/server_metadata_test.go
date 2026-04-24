package httpapi_test

import (
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
