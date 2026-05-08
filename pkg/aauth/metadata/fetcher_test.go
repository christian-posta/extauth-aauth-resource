package metadata_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"aauth-service/pkg/aauth/metadata"
)

func serveJSON(t *testing.T, path string, body interface{}) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(body)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestFetcher_FetchResource(t *testing.T) {
	expected := &metadata.ResourceMetadata{
		Resource: "https://resource.example",
		JwksURI:  "https://resource.example/.well-known/jwks.json",
	}
	srv := serveJSON(t, "/.well-known/aauth-resource.json", expected)

	f := metadata.NewFetcher(metadata.FetcherOptions{HTTPClient: srv.Client()})
	got, err := f.FetchResource(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("FetchResource: %v", err)
	}
	if got.Resource != expected.Resource {
		t.Errorf("Resource: got %q want %q", got.Resource, expected.Resource)
	}
	if got.JwksURI != expected.JwksURI {
		t.Errorf("JwksURI: got %q want %q", got.JwksURI, expected.JwksURI)
	}
}

func TestFetcher_FetchPersonServer(t *testing.T) {
	expected := &metadata.PersonServerMetadata{
		Issuer:        "https://ps.example",
		TokenEndpoint: "https://ps.example/token",
		JwksURI:       "https://ps.example/.well-known/jwks.json",
	}
	srv := serveJSON(t, "/.well-known/aauth-person.json", expected)

	f := metadata.NewFetcher(metadata.FetcherOptions{HTTPClient: srv.Client()})
	got, err := f.FetchPersonServer(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("FetchPersonServer: %v", err)
	}
	if got.Issuer != expected.Issuer {
		t.Errorf("Issuer: got %q want %q", got.Issuer, expected.Issuer)
	}
	if got.TokenEndpoint != expected.TokenEndpoint {
		t.Errorf("TokenEndpoint: got %q want %q", got.TokenEndpoint, expected.TokenEndpoint)
	}
}

func TestFetcher_FetchAuthServer(t *testing.T) {
	expected := &metadata.AuthServerMetadata{
		Issuer:        "https://as.example",
		TokenEndpoint: "https://as.example/token",
		JwksURI:       "https://as.example/.well-known/jwks.json",
	}
	srv := serveJSON(t, "/.well-known/aauth-access.json", expected)

	f := metadata.NewFetcher(metadata.FetcherOptions{HTTPClient: srv.Client()})
	got, err := f.FetchAuthServer(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("FetchAuthServer: %v", err)
	}
	if got.Issuer != expected.Issuer {
		t.Errorf("Issuer: got %q want %q", got.Issuer, expected.Issuer)
	}
}

func TestFetcher_FetchAgentServer(t *testing.T) {
	expected := &metadata.AgentServerMetadata{
		Issuer:      "https://agent.example",
		JwksURI:     "https://agent.example/.well-known/jwks.json",
		ClientName:  "My Agent",
	}
	srv := serveJSON(t, "/.well-known/aauth-agent.json", expected)

	f := metadata.NewFetcher(metadata.FetcherOptions{HTTPClient: srv.Client()})
	got, err := f.FetchAgentServer(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("FetchAgentServer: %v", err)
	}
	if got.Issuer != expected.Issuer {
		t.Errorf("Issuer: got %q want %q", got.Issuer, expected.Issuer)
	}
	if got.ClientName != expected.ClientName {
		t.Errorf("ClientName: got %q want %q", got.ClientName, expected.ClientName)
	}
}

func TestFetcher_NotFoundReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)

	f := metadata.NewFetcher(metadata.FetcherOptions{HTTPClient: srv.Client()})
	_, err := f.FetchPersonServer(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("expected error for 404 response")
	}
}

func TestFetcher_InvalidServerIDReturnsError(t *testing.T) {
	f := metadata.NewFetcher(metadata.FetcherOptions{})
	_, err := f.FetchPersonServer(context.Background(), "not-a-valid-id")
	if err == nil {
		t.Fatal("expected error for invalid server identifier")
	}
}

func TestFetcher_HTTPSServerIDPassesValidation(t *testing.T) {
	expected := &metadata.PersonServerMetadata{
		Issuer:        "https://ps.example",
		TokenEndpoint: "https://ps.example/token",
		JwksURI:       "https://ps.example/.well-known/jwks.json",
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/aauth-person.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(expected)
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)

	f := metadata.NewFetcher(metadata.FetcherOptions{HTTPClient: srv.Client()})
	_, err := f.FetchPersonServer(context.Background(), "https://ps.example")
	// This will fail on the network call (not a real server) but should pass validation
	// We just check it's not a "invalid server identifier" error
	if err != nil && containsStr(err.Error(), "invalid server identifier") {
		t.Errorf("unexpected validation error: %v", err)
	}
}

func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstr(s, substr))
}

func containsSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
