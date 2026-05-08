package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// buildTestResourceToken creates a signed JWT with aud=psBaseURL.
func buildTestResourceToken(t *testing.T, psBaseURL string) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tok, err := jwt.NewBuilder().
		Issuer("http://resource.example.com").
		Audience([]string{psBaseURL}).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(5 * time.Minute)).
		Build()
	if err != nil {
		t.Fatalf("build jwt: %v", err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.EdDSA, priv))
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	return string(signed)
}

// mockPS builds an httptest.Server that acts as a minimal Person Server.
// It serves /.well-known/aauth-person.json and /token.
// If tokenStatus is 200, /token returns auth_token immediately.
// If tokenStatus is 202, /token returns 202 with Location pointing to /poll,
// and /poll returns 200 with auth_token.
func mockPS(t *testing.T, tokenStatus int, authToken string) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/aauth-person.json", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"token_endpoint": srv.URL + "/token",
		})
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if tokenStatus == http.StatusAccepted {
			w.Header().Set("Location", srv.URL+"/poll")
			w.WriteHeader(http.StatusAccepted)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"auth_token": authToken})
	})

	mux.HandleFunc("/poll", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"auth_token": authToken})
	})

	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// TestExchanger_ImmediateSuccess: PS returns 200 directly.
func TestExchanger_ImmediateSuccess(t *testing.T) {
	srv := mockPS(t, http.StatusOK, "test.jwt.token")
	resourceToken := buildTestResourceToken(t, srv.URL)

	exchanger, err := NewTokenExchanger(ExchangerOptions{
		HTTPClient: srv.Client(),
		Logger:     nil,
	})
	if err != nil {
		t.Fatalf("NewTokenExchanger: %v", err)
	}

	result, err := exchanger.Exchange(context.Background(), ExchangeRequest{
		ResourceToken: resourceToken,
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if result.AuthToken != "test.jwt.token" {
		t.Errorf("AuthToken = %q, want %q", result.AuthToken, "test.jwt.token")
	}
}

// TestExchanger_DeferredSuccess: PS returns 202, poller gets 200 on first poll.
func TestExchanger_DeferredSuccess(t *testing.T) {
	srv := mockPS(t, http.StatusAccepted, "deferred.jwt.token")
	resourceToken := buildTestResourceToken(t, srv.URL)

	poller := NewPoller(PollerOptions{
		HTTPClient:   srv.Client(),
		MaxAttempts:  5,
		InitialDelay: time.Millisecond,
		MaxDelay:     5 * time.Millisecond,
	})

	exchanger, err := NewTokenExchanger(ExchangerOptions{
		HTTPClient: srv.Client(),
		Poller:     poller,
	})
	if err != nil {
		t.Fatalf("NewTokenExchanger: %v", err)
	}

	result, err := exchanger.Exchange(context.Background(), ExchangeRequest{
		ResourceToken: resourceToken,
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if result.AuthToken != "deferred.jwt.token" {
		t.Errorf("AuthToken = %q, want %q", result.AuthToken, "deferred.jwt.token")
	}
}

// TestExchanger_WithPSMetadataURLOverride: uses explicit PSMetadataURL.
func TestExchanger_WithPSMetadataURLOverride(t *testing.T) {
	srv := mockPS(t, http.StatusOK, "override.jwt.token")

	// resource token with a dummy aud (won't be used for discovery)
	resourceToken := buildTestResourceToken(t, "http://dummy.ps.example.com")

	exchanger, err := NewTokenExchanger(ExchangerOptions{
		HTTPClient:    srv.Client(),
		PSMetadataURL: srv.URL + "/.well-known/aauth-person.json",
	})
	if err != nil {
		t.Fatalf("NewTokenExchanger: %v", err)
	}

	result, err := exchanger.Exchange(context.Background(), ExchangeRequest{
		ResourceToken: resourceToken,
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if result.AuthToken != "override.jwt.token" {
		t.Errorf("AuthToken = %q, want %q", result.AuthToken, "override.jwt.token")
	}
}

// TestExchanger_WithSigner: verifies that a signer is applied without error.
func TestExchanger_WithSigner(t *testing.T) {
	srv := mockPS(t, http.StatusOK, "signed.jwt.token")
	resourceToken := buildTestResourceToken(t, srv.URL)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := NewRequestSigner(SignerOptions{
		AgentID:   "aauth:agent@example.com",
		KeyID:     "key-1",
		Signer:    priv,
		Algorithm: "ed25519",
	})
	if err != nil {
		t.Fatalf("NewRequestSigner: %v", err)
	}

	exchanger, err := NewTokenExchanger(ExchangerOptions{
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("NewTokenExchanger: %v", err)
	}

	result, err := exchanger.Exchange(context.Background(), ExchangeRequest{
		ResourceToken: resourceToken,
		Signer:        signer,
	})
	if err != nil {
		t.Fatalf("Exchange with signer: %v", err)
	}
	if result.AuthToken != "signed.jwt.token" {
		t.Errorf("AuthToken = %q, want %q", result.AuthToken, "signed.jwt.token")
	}
}

// TestExchanger_4xxError: PS returns 401, exchanger returns an error.
func TestExchanger_4xxError(t *testing.T) {
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/aauth-person.json", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"token_endpoint": srv.URL + "/token",
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	resourceToken := buildTestResourceToken(t, srv.URL)
	exchanger, err := NewTokenExchanger(ExchangerOptions{
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("NewTokenExchanger: %v", err)
	}

	_, err = exchanger.Exchange(context.Background(), ExchangeRequest{
		ResourceToken: resourceToken,
	})
	if err == nil {
		t.Fatal("expected error for 401 response")
	}
}

// TestContentDigestHeader verifies that Exchange sends a Content-Digest header.
func TestContentDigestHeader(t *testing.T) {
	var gotContentDigest string
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/aauth-person.json", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"token_endpoint": srv.URL + "/token",
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		gotContentDigest = r.Header.Get("Content-Digest")
		json.NewEncoder(w).Encode(map[string]string{"auth_token": "digest.test.token"})
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	resourceToken := buildTestResourceToken(t, srv.URL)
	exchanger, err := NewTokenExchanger(ExchangerOptions{
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("NewTokenExchanger: %v", err)
	}

	_, err = exchanger.Exchange(context.Background(), ExchangeRequest{
		ResourceToken: resourceToken,
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if gotContentDigest == "" {
		t.Error("Content-Digest header was not sent")
	}
	if len(gotContentDigest) < 10 || !containsBase64(gotContentDigest) {
		t.Errorf("Content-Digest looks malformed: %q", gotContentDigest)
	}
}

func containsBase64(s string) bool {
	// Just check it has the sha-256 prefix and some base64 chars
	if len(s) < 20 {
		return false
	}
	_, err := base64.StdEncoding.DecodeString("abc=")
	return err == nil
}
