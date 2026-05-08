package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	ahttp "aauth-service/pkg/aauth/http"
)

// testServer builds a server that returns canned responses in sequence indexed by
// an atomic counter. Each entry is a func that writes the response.
func testServer(t *testing.T, handlers []http.HandlerFunc) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var counter atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idx := int(counter.Add(1)) - 1
		if idx >= len(handlers) {
			idx = len(handlers) - 1
		}
		handlers[idx](w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, &counter
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// Test 1: immediate 200 — success without any polling loop.
func TestPoller_ImmediateSuccess(t *testing.T) {
	srv, _ := testServer(t, []http.HandlerFunc{
		func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, map[string]string{"auth_token": "tok.immediate"})
		},
	})

	p := NewPoller(PollerOptions{
		HTTPClient:   srv.Client(),
		MaxAttempts:  5,
		InitialDelay: time.Millisecond,
	})
	result, err := p.Poll(context.Background(), srv.URL+"/poll")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected success, got error: %s", result.Error)
	}
	if result.AuthToken != "tok.immediate" {
		t.Errorf("AuthToken = %q, want %q", result.AuthToken, "tok.immediate")
	}
}

// Test 2: two pending 202s then a 200 success.
func TestPoller_PendingThenSuccess(t *testing.T) {
	pending := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "0")
		writeJSON(w, http.StatusAccepted, map[string]string{"status": ahttp.StatusPending})
	}
	srv, counter := testServer(t, []http.HandlerFunc{
		pending,
		pending,
		func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, map[string]string{"auth_token": "tok.after.pending"})
		},
	})

	p := NewPoller(PollerOptions{
		HTTPClient:   srv.Client(),
		MaxAttempts:  10,
		InitialDelay: time.Millisecond,
		MaxDelay:     5 * time.Millisecond,
	})
	result, err := p.Poll(context.Background(), srv.URL+"/poll")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected success, got error: %s", result.Error)
	}
	if result.AuthToken != "tok.after.pending" {
		t.Errorf("AuthToken = %q", result.AuthToken)
	}
	if counter.Load() != 3 {
		t.Errorf("expected 3 requests, got %d", counter.Load())
	}
}

// Test 3: pending → interaction → pending → success; OnInteraction called exactly once.
func TestPoller_InteractionThenSuccess(t *testing.T) {
	var interactionCalls atomic.Int32

	handlers := []http.HandlerFunc{
		// First: 202 with requirement=interaction
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Retry-After", "0")
			writeJSON(w, http.StatusAccepted, map[string]interface{}{
				"status":      ahttp.StatusPending,
				"requirement": "interaction",
				"url":         "http://interact.example.com",
				"code":        "CODE123",
			})
		},
		// Second: status=interacting
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Retry-After", "0")
			writeJSON(w, http.StatusAccepted, map[string]string{"status": ahttp.StatusInteracting})
		},
		// Third: pending (no requirement)
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Retry-After", "0")
			writeJSON(w, http.StatusAccepted, map[string]string{"status": ahttp.StatusPending})
		},
		// Fourth: success
		func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, map[string]string{"auth_token": "tok.after.interact"})
		},
	}

	srv, _ := testServer(t, handlers)

	p := NewPoller(PollerOptions{
		HTTPClient:   srv.Client(),
		MaxAttempts:  10,
		InitialDelay: time.Millisecond,
		MaxDelay:     5 * time.Millisecond,
		OnInteraction: func(ctx context.Context, url, code string) error {
			interactionCalls.Add(1)
			want := "http://interact.example.com?code=CODE123"
			if url != want {
				t.Errorf("OnInteraction url = %q, want %q", url, want)
			}
			if code != "CODE123" {
				t.Errorf("OnInteraction code = %q, want %q", code, "CODE123")
			}
			return nil
		},
	})

	result, err := p.Poll(context.Background(), srv.URL+"/poll")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected success, got: %s", result.Error)
	}
	if result.AuthToken != "tok.after.interact" {
		t.Errorf("AuthToken = %q", result.AuthToken)
	}
	if interactionCalls.Load() != 1 {
		t.Errorf("OnInteraction called %d times, want 1", interactionCalls.Load())
	}
}

// Test 4: 403 → denied.
func TestPoller_Denied(t *testing.T) {
	srv, _ := testServer(t, []http.HandlerFunc{
		func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "access_denied"})
		},
	})

	p := NewPoller(PollerOptions{
		HTTPClient:   srv.Client(),
		MaxAttempts:  5,
		InitialDelay: time.Millisecond,
	})
	result, err := p.Poll(context.Background(), srv.URL+"/poll")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Success {
		t.Fatal("expected failure, got success")
	}
	if result.Error != "access_denied" {
		t.Errorf("Error = %q, want %q", result.Error, "access_denied")
	}
}

// Test 5: 408 → expired.
func TestPoller_Expired(t *testing.T) {
	srv, _ := testServer(t, []http.HandlerFunc{
		func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusRequestTimeout, map[string]string{"error": "expired"})
		},
	})

	p := NewPoller(PollerOptions{
		HTTPClient:   srv.Client(),
		MaxAttempts:  5,
		InitialDelay: time.Millisecond,
	})
	result, err := p.Poll(context.Background(), srv.URL+"/poll")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Success {
		t.Fatal("expected failure")
	}
	if result.Status != "expired" {
		t.Errorf("Status = %q, want expired", result.Status)
	}
}

// Test 6: 410 → cancelled.
func TestPoller_Cancelled(t *testing.T) {
	srv, _ := testServer(t, []http.HandlerFunc{
		func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusGone, map[string]string{"error": "cancelled"})
		},
	})

	p := NewPoller(PollerOptions{
		HTTPClient:   srv.Client(),
		MaxAttempts:  5,
		InitialDelay: time.Millisecond,
	})
	result, err := p.Poll(context.Background(), srv.URL+"/poll")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Success {
		t.Fatal("expected failure")
	}
	if result.Status != "cancelled" {
		t.Errorf("Status = %q, want cancelled", result.Status)
	}
}

// Test 7: 429 with Retry-After honored, then success.
func TestPoller_RateLimited(t *testing.T) {
	handlers := []http.HandlerFunc{
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Retry-After", "0")
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "slow_down"})
		},
		func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, map[string]string{"auth_token": "tok.after.ratelimit"})
		},
	}
	srv, counter := testServer(t, handlers)

	p := NewPoller(PollerOptions{
		HTTPClient:   srv.Client(),
		MaxAttempts:  5,
		InitialDelay: time.Millisecond,
		MaxDelay:     5 * time.Millisecond,
	})
	result, err := p.Poll(context.Background(), srv.URL+"/poll")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected success, got: %s", result.Error)
	}
	if counter.Load() != 2 {
		t.Errorf("expected 2 requests, got %d", counter.Load())
	}
}

// Test 8: max attempts exceeded.
func TestPoller_MaxAttemptsExceeded(t *testing.T) {
	srv, counter := testServer(t, []http.HandlerFunc{
		// always returns pending
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Retry-After", "0")
			writeJSON(w, http.StatusAccepted, map[string]string{"status": ahttp.StatusPending})
		},
	})
	// Make the server always re-use the last handler
	_ = counter

	p := NewPoller(PollerOptions{
		HTTPClient:   srv.Client(),
		MaxAttempts:  3,
		InitialDelay: time.Millisecond,
		MaxDelay:     5 * time.Millisecond,
	})
	result, err := p.Poll(context.Background(), srv.URL+"/poll")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Success {
		t.Fatal("expected failure due to max attempts")
	}
	if result.Error != "max attempts exceeded" {
		t.Errorf("Error = %q, want %q", result.Error, "max attempts exceeded")
	}
}

// Test 9: context cancellation stops polling.
func TestPoller_ContextCancellation(t *testing.T) {
	var callCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.Header().Set("Retry-After", "10") // long delay that context cancels before
		writeJSON(w, http.StatusAccepted, map[string]string{"status": ahttp.StatusPending})
	}))
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithCancel(context.Background())

	p := NewPoller(PollerOptions{
		HTTPClient:   srv.Client(),
		MaxAttempts:  10,
		InitialDelay: 50 * time.Millisecond,
		MaxDelay:     100 * time.Millisecond,
	})

	done := make(chan struct{})
	var result *PollResult
	var pollErr error
	go func() {
		result, pollErr = p.Poll(ctx, srv.URL+"/poll")
		close(done)
	}()

	// Give one poll a chance to complete, then cancel
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Poll did not return after context cancellation")
	}

	if pollErr == nil && (result == nil || result.Success) {
		t.Error("expected failure after context cancellation")
	}
}

// Test 10: Retry-After as an HTTP-date string.
func TestPoller_RetryAfterHTTPDate(t *testing.T) {
	// Use a past date so the parsed duration is 0 and we don't wait
	pastDate := time.Now().Add(-10 * time.Second).UTC().Format(http.TimeFormat)

	handlers := []http.HandlerFunc{
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Retry-After", pastDate)
			writeJSON(w, http.StatusAccepted, map[string]string{"status": ahttp.StatusPending})
		},
		func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, map[string]string{"auth_token": "tok.after.date"})
		},
	}
	srv, counter := testServer(t, handlers)

	p := NewPoller(PollerOptions{
		HTTPClient:   srv.Client(),
		MaxAttempts:  5,
		InitialDelay: time.Millisecond,
		MaxDelay:     5 * time.Millisecond,
	})

	result, err := p.Poll(context.Background(), srv.URL+"/poll")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected success, got: %s", result.Error)
	}
	if counter.Load() != 2 {
		t.Errorf("expected 2 requests, got %d", counter.Load())
	}
}

// TestParseRetryAfter tests the Retry-After header parser directly.
func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	tests := []struct {
		val       string
		want      time.Duration
		wantFound bool
	}{
		{"", 0, false},
		{"5", 5 * time.Second, true},
		{"0", 0, true},
		{"invalid", 0, false},
		{now.Add(30 * time.Second).UTC().Format(http.TimeFormat), 30 * time.Second, true},
		{now.Add(-5 * time.Second).UTC().Format(http.TimeFormat), 0, true}, // past date → 0, found=true
	}

	for _, tc := range tests {
		got, found := parseRetryAfter(tc.val, clock)
		if found != tc.wantFound {
			t.Errorf("parseRetryAfter(%q) found=%v, want %v", tc.val, found, tc.wantFound)
		}
		// Allow 1s tolerance for date parsing rounding
		diff := got - tc.want
		if diff < 0 {
			diff = -diff
		}
		if diff > time.Second {
			t.Errorf("parseRetryAfter(%q) = %v, want %v", tc.val, got, tc.want)
		}
	}
}
