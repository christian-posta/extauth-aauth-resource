package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestExchangeResourceToken_EndToEnd wires together a mock resource (returning a
// resource-token challenge) and a mock PS (performing the exchange) using
// ExchangeResourceToken.
func TestExchangeResourceToken_EndToEnd(t *testing.T) {
	var psSrv *httptest.Server
	psMux := http.NewServeMux()
	psMux.HandleFunc("/.well-known/aauth-person.json", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"token_endpoint": psSrv.URL + "/token",
		})
	})
	psMux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"auth_token": "e2e.auth.token"})
	})
	psSrv = httptest.NewServer(psMux)
	t.Cleanup(psSrv.Close)

	// Build a resource token whose aud points at the PS.
	resourceToken := buildTestResourceToken(t, psSrv.URL)

	result, err := ExchangeResourceToken(context.Background(), ExchangeResourceTokenOptions{
		ResourceToken: resourceToken,
		HTTPClient:    psSrv.Client(),
		MaxPolls:      5,
		Logger:        nil,
		Clock:         time.Now,
	})
	if err != nil {
		t.Fatalf("ExchangeResourceToken: %v", err)
	}
	if result.AuthToken != "e2e.auth.token" {
		t.Errorf("AuthToken = %q, want %q", result.AuthToken, "e2e.auth.token")
	}
}

// TestExchangeResourceToken_Deferred tests the 202 → poll → 200 path end-to-end.
func TestExchangeResourceToken_Deferred(t *testing.T) {
	var psSrv *httptest.Server
	psMux := http.NewServeMux()
	psMux.HandleFunc("/.well-known/aauth-person.json", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"token_endpoint": psSrv.URL + "/token",
		})
	})
	psMux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", psSrv.URL+"/poll")
		w.WriteHeader(http.StatusAccepted)
	})
	psMux.HandleFunc("/poll", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"auth_token": "deferred.e2e.token"})
	})
	psSrv = httptest.NewServer(psMux)
	t.Cleanup(psSrv.Close)

	resourceToken := buildTestResourceToken(t, psSrv.URL)

	result, err := ExchangeResourceToken(context.Background(), ExchangeResourceTokenOptions{
		ResourceToken: resourceToken,
		HTTPClient:    psSrv.Client(),
		MaxPolls:      5,
		Logger:        nil,
	})
	if err != nil {
		t.Fatalf("ExchangeResourceToken deferred: %v", err)
	}
	if result.AuthToken != "deferred.e2e.token" {
		t.Errorf("AuthToken = %q, want %q", result.AuthToken, "deferred.e2e.token")
	}
}

// TestExchangeResourceToken_WithInteractionCallback verifies that the OnInteraction
// hook is wired through correctly.
func TestExchangeResourceToken_WithInteractionCallback(t *testing.T) {
	var interacted bool

	var psSrv *httptest.Server
	var pollCount atomic.Int32
	psMux := http.NewServeMux()
	psMux.HandleFunc("/.well-known/aauth-person.json", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"token_endpoint": psSrv.URL + "/token",
		})
	})
	psMux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", psSrv.URL+"/poll")
		w.WriteHeader(http.StatusAccepted)
	})
	psMux.HandleFunc("/poll", func(w http.ResponseWriter, r *http.Request) {
		n := pollCount.Add(1)
		if n == 1 {
			w.Header().Set("Retry-After", "0")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":      "pending",
				"requirement": "interaction",
				"url":         "http://interact.example.com/login",
				"code":        "XYZ789",
			})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"auth_token": "interact.e2e.token"})
	})
	psSrv = httptest.NewServer(psMux)
	t.Cleanup(psSrv.Close)

	resourceToken := buildTestResourceToken(t, psSrv.URL)

	result, err := ExchangeResourceToken(context.Background(), ExchangeResourceTokenOptions{
		ResourceToken: resourceToken,
		HTTPClient:    psSrv.Client(),
		MaxPolls:      10,
		OnInteraction: func(ctx context.Context, url, code string) error {
			interacted = true
			return nil
		},
	})
	if err != nil {
		t.Fatalf("ExchangeResourceToken with interaction: %v", err)
	}
	if result.AuthToken != "interact.e2e.token" {
		t.Errorf("AuthToken = %q, want %q", result.AuthToken, "interact.e2e.token")
	}
	if !interacted {
		t.Error("OnInteraction was not called")
	}
}
