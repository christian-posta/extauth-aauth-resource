package keys_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"

	"aauth-service/pkg/aauth/keys"
)

func makeTestJWKSServer(t *testing.T, kid string) (*httptest.Server, *int64) {
	t.Helper()
	var hits int64
	set := jwk.NewSet()
	k, err := jwk.FromRaw([]byte("00000000000000000000000000000000"))
	if err != nil {
		t.Fatalf("build test key: %v", err)
	}
	if err := k.Set(jwk.KeyIDKey, kid); err != nil {
		t.Fatalf("set kid: %v", err)
	}
	if err := k.Set(jwk.AlgorithmKey, jwa.HS256); err != nil {
		t.Fatalf("set alg: %v", err)
	}
	if err := set.AddKey(k); err != nil {
		t.Fatalf("add key: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		b, _ := json.Marshal(set)
		w.Write(b)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func TestFetcher_FirstCallFetches(t *testing.T) {
	srv, hits := makeTestJWKSServer(t, "key-1")
	now := time.Now()
	f := keys.NewJWKSFetcher(keys.FetcherOptions{
		HTTPClient: srv.Client(),
		DefaultTTL: 5 * time.Minute,
		Clock:      func() time.Time { return now },
	})

	set, err := f.Get(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if set.Len() == 0 {
		t.Error("expected non-empty JWKS set")
	}
	if atomic.LoadInt64(hits) != 1 {
		t.Errorf("expected 1 HTTP hit, got %d", atomic.LoadInt64(hits))
	}
}

func TestFetcher_SecondCallWithinTTLIsCached(t *testing.T) {
	srv, hits := makeTestJWKSServer(t, "key-1")
	now := time.Now()
	f := keys.NewJWKSFetcher(keys.FetcherOptions{
		HTTPClient: srv.Client(),
		DefaultTTL: 5 * time.Minute,
		Clock:      func() time.Time { return now },
	})

	if _, err := f.Get(context.Background(), srv.URL); err != nil {
		t.Fatalf("first Get: %v", err)
	}
	if _, err := f.Get(context.Background(), srv.URL); err != nil {
		t.Fatalf("second Get: %v", err)
	}
	if atomic.LoadInt64(hits) != 1 {
		t.Errorf("expected 1 HTTP hit (cached), got %d", atomic.LoadInt64(hits))
	}
}

func TestFetcher_AfterMaxAgeEvictsAndRefetches(t *testing.T) {
	srv, hits := makeTestJWKSServer(t, "key-1")
	now := time.Now()
	clock := &now
	f := keys.NewJWKSFetcher(keys.FetcherOptions{
		HTTPClient: srv.Client(),
		DefaultTTL: 5 * time.Minute,
		MaxAge:     10 * time.Minute,
		MinRefetch: time.Second,
		Clock:      func() time.Time { return *clock },
	})

	if _, err := f.Get(context.Background(), srv.URL); err != nil {
		t.Fatalf("first Get: %v", err)
	}

	advanced := now.Add(11 * time.Minute)
	clock = &advanced

	if _, err := f.Get(context.Background(), srv.URL); err != nil {
		t.Fatalf("second Get after MaxAge: %v", err)
	}
	if atomic.LoadInt64(hits) != 2 {
		t.Errorf("expected 2 HTTP hits (evict+refetch), got %d", atomic.LoadInt64(hits))
	}
}

func TestFetcher_MinRefetchPreventsRapidRefetch(t *testing.T) {
	srv, hits := makeTestJWKSServer(t, "key-1")
	now := time.Now()
	clock := &now
	f := keys.NewJWKSFetcher(keys.FetcherOptions{
		HTTPClient: srv.Client(),
		DefaultTTL: time.Second,
		MaxAge:     24 * time.Hour,
		MinRefetch: 60 * time.Second,
		Clock:      func() time.Time { return *clock },
	})

	if _, err := f.Get(context.Background(), srv.URL); err != nil {
		t.Fatalf("first Get: %v", err)
	}

	// Advance past DefaultTTL but not past MinRefetch
	advanced := now.Add(5 * time.Second)
	clock = &advanced

	if _, err := f.Get(context.Background(), srv.URL); err != nil {
		t.Fatalf("second Get: %v", err)
	}
	if atomic.LoadInt64(hits) != 1 {
		t.Errorf("expected 1 HTTP hit (rate limited), got %d", atomic.LoadInt64(hits))
	}
}

func TestFetcher_MinRefetchAllowsRefetchAfterInterval(t *testing.T) {
	srv, hits := makeTestJWKSServer(t, "key-1")
	now := time.Now()
	clock := &now
	f := keys.NewJWKSFetcher(keys.FetcherOptions{
		HTTPClient: srv.Client(),
		DefaultTTL: time.Second,
		MaxAge:     24 * time.Hour,
		MinRefetch: 30 * time.Second,
		Clock:      func() time.Time { return *clock },
	})

	if _, err := f.Get(context.Background(), srv.URL); err != nil {
		t.Fatalf("first Get: %v", err)
	}

	// Advance past both DefaultTTL and MinRefetch
	advanced := now.Add(60 * time.Second)
	clock = &advanced

	if _, err := f.Get(context.Background(), srv.URL); err != nil {
		t.Fatalf("second Get: %v", err)
	}
	if atomic.LoadInt64(hits) != 2 {
		t.Errorf("expected 2 HTTP hits, got %d", atomic.LoadInt64(hits))
	}
}

func TestFetcher_GetForKidReturnsCorrectKey(t *testing.T) {
	srv, _ := makeTestJWKSServer(t, "key-1")
	now := time.Now()
	f := keys.NewJWKSFetcher(keys.FetcherOptions{
		HTTPClient: srv.Client(),
		DefaultTTL: 5 * time.Minute,
		Clock:      func() time.Time { return now },
	})

	key, err := f.GetForKid(context.Background(), srv.URL, "key-1")
	if err != nil {
		t.Fatalf("GetForKid: %v", err)
	}
	if key.KeyID() != "key-1" {
		t.Errorf("expected kid=key-1, got %q", key.KeyID())
	}
}

func TestFetcher_GetForKidUnknownKidTriggersRefetch(t *testing.T) {
	srv, hits := makeTestJWKSServer(t, "key-1")
	now := time.Now()
	clock := &now
	f := keys.NewJWKSFetcher(keys.FetcherOptions{
		HTTPClient: srv.Client(),
		DefaultTTL: 5 * time.Minute,
		MinRefetch: 30 * time.Second,
		Clock:      func() time.Time { return *clock },
	})

	// Pre-populate cache at t=now
	if _, err := f.Get(context.Background(), srv.URL); err != nil {
		t.Fatalf("initial Get: %v", err)
	}

	// Advance clock past MinRefetch so refetch is allowed
	advanced := now.Add(60 * time.Second)
	clock = &advanced

	// Request an unknown kid; should refetch once (cache is still within TTL but kid not found)
	_, err := f.GetForKid(context.Background(), srv.URL, "unknown-kid")
	if err == nil {
		t.Fatal("expected error for unknown kid")
	}
	if atomic.LoadInt64(hits) != 2 {
		t.Errorf("expected 2 HTTP hits (initial + refetch for unknown kid), got %d", atomic.LoadInt64(hits))
	}
}

func TestFetcher_GetForKidRateLimitedOnUnknownKid(t *testing.T) {
	srv, hits := makeTestJWKSServer(t, "key-1")
	now := time.Now()
	f := keys.NewJWKSFetcher(keys.FetcherOptions{
		HTTPClient: srv.Client(),
		DefaultTTL: 5 * time.Minute,
		MinRefetch: 60 * time.Second,
		Clock:      func() time.Time { return now },
	})

	// Pre-populate cache (this records lastAttempt = now)
	if _, err := f.Get(context.Background(), srv.URL); err != nil {
		t.Fatalf("initial Get: %v", err)
	}

	// Request an unknown kid immediately — should not refetch due to rate limit
	_, err := f.GetForKid(context.Background(), srv.URL, "unknown-kid")
	if err == nil {
		t.Fatal("expected error for unknown kid")
	}
	if atomic.LoadInt64(hits) != 1 {
		t.Errorf("expected 1 HTTP hit (rate limited refetch), got %d", atomic.LoadInt64(hits))
	}
}
