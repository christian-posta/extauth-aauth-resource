package keys

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

type FetcherOptions struct {
	HTTPClient *http.Client
	DefaultTTL time.Duration
	MaxAge     time.Duration
	MinRefetch time.Duration
	Logger     *slog.Logger
	Clock      func() time.Time
}

type cacheEntry struct {
	set         jwk.Set
	fetchedAt   time.Time
	lastAttempt time.Time
}

type JWKSFetcher struct {
	mu    sync.RWMutex
	cache map[string]*cacheEntry
	opts  FetcherOptions
}

func NewJWKSFetcher(opts FetcherOptions) *JWKSFetcher {
	if opts.DefaultTTL == 0 {
		opts.DefaultTTL = 5 * time.Minute
	}
	if opts.MaxAge == 0 {
		opts.MaxAge = 24 * time.Hour
	}
	if opts.MinRefetch == 0 {
		opts.MinRefetch = 60 * time.Second
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = http.DefaultClient
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	return &JWKSFetcher{
		cache: make(map[string]*cacheEntry),
		opts:  opts,
	}
}

func (f *JWKSFetcher) Get(ctx context.Context, jwksURI string) (jwk.Set, error) {
	now := f.opts.Clock()

	f.mu.RLock()
	entry := f.cache[jwksURI]
	f.mu.RUnlock()

	if entry != nil {
		age := now.Sub(entry.fetchedAt)
		if age >= f.opts.MaxAge {
			return f.refetch(ctx, jwksURI, now)
		}
		if age < f.opts.DefaultTTL {
			return entry.set, nil
		}
		if now.Sub(entry.lastAttempt) < f.opts.MinRefetch {
			return entry.set, nil
		}
		return f.refetch(ctx, jwksURI, now)
	}

	return f.refetch(ctx, jwksURI, now)
}

func (f *JWKSFetcher) GetForKid(ctx context.Context, jwksURI, kid string) (jwk.Key, error) {
	now := f.opts.Clock()

	set, err := f.Get(ctx, jwksURI)
	if err != nil {
		return nil, err
	}

	if key, ok := set.LookupKeyID(kid); ok {
		return key, nil
	}

	f.mu.RLock()
	entry := f.cache[jwksURI]
	f.mu.RUnlock()

	if entry != nil && now.Sub(entry.lastAttempt) < f.opts.MinRefetch {
		return nil, fmt.Errorf("key %q not found in JWKS %s", kid, jwksURI)
	}

	set, err = f.refetch(ctx, jwksURI, now)
	if err != nil {
		return nil, err
	}

	if key, ok := set.LookupKeyID(kid); ok {
		return key, nil
	}
	return nil, fmt.Errorf("key %q not found in JWKS %s", kid, jwksURI)
}

func (f *JWKSFetcher) refetch(ctx context.Context, jwksURI string, now time.Time) (jwk.Set, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	entry := f.cache[jwksURI]
	if entry != nil {
		if now.Sub(entry.lastAttempt) < f.opts.MinRefetch {
			return entry.set, nil
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return nil, fmt.Errorf("jwks: build request for %s: %w", jwksURI, err)
	}

	resp, err := f.opts.HTTPClient.Do(req)
	if err != nil {
		if entry != nil {
			entry.lastAttempt = now
		}
		return nil, fmt.Errorf("jwks: fetch %s: %w", jwksURI, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if entry != nil {
			entry.lastAttempt = now
		}
		return nil, fmt.Errorf("jwks: %s returned status %d", jwksURI, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("jwks: read response from %s: %w", jwksURI, err)
	}

	set, err := jwk.Parse(body)
	if err != nil {
		return nil, fmt.Errorf("jwks: parse response from %s: %w", jwksURI, err)
	}

	f.cache[jwksURI] = &cacheEntry{
		set:         set,
		fetchedAt:   now,
		lastAttempt: now,
	}
	f.opts.Logger.DebugContext(ctx, "jwks fetched", "uri", jwksURI)
	return set, nil
}
