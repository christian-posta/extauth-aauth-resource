package jwksfetch

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"aauth-service/internal/config"
	"aauth-service/internal/metrics"
)

type Client interface {
	Get(ctx context.Context, uri string) (jwk.Set, error)
	GetMetadata(ctx context.Context, uri string) (map[string]interface{}, error)
	Invalidate(uri string)
}

type DefaultClient struct {
	mu         sync.RWMutex
	allowList  map[string]bool
	httpClient *http.Client
	cache      *jwk.Cache
	successTTL time.Duration
}

func NewClient(cfg *config.Config) *DefaultClient {
	allowList := make(map[string]bool)
	for _, rcYAML := range cfg.Resources {
		rc := rcYAML.ToDomain()
		for _, authServer := range rc.AuthServers {
			allowList[authServer.JwksURI] = true
			// Add AAuth spec discovery URLs: {iss}/.well-known/{dwk}
			base := strings.TrimRight(authServer.Issuer, "/")
			allowList[base+"/.well-known/aauth-access.json"] = true
			allowList[base+"/.well-known/aauth-person.json"] = true
		}
		for _, agentServer := range rc.AgentServers {
			allowList[agentServer.JwksURI] = true
			// Add AAuth spec discovery URL: {iss}/.well-known/aauth-agent.json
			base := strings.TrimRight(agentServer.Issuer, "/")
			allowList[base+"/.well-known/aauth-agent.json"] = true
		}
	}

	httpClient := &http.Client{
		Timeout: 5 * time.Second,
	}

	successTTL := cfg.JwksCache.SuccessTTL
	if successTTL == 0 {
		successTTL = 5 * time.Minute
	}

	cache := jwk.NewCache(context.Background(), jwk.WithRefreshWindow(successTTL))

	return &DefaultClient{
		allowList:  allowList,
		httpClient: httpClient,
		cache:      cache,
		successTTL: successTTL,
	}
}

func (c *DefaultClient) Get(ctx context.Context, uri string) (jwk.Set, error) {
	c.cache.Register(uri, jwk.WithMinRefreshInterval(c.successTTL))

	set, err := c.cache.Get(ctx, uri)
	if err != nil {
		metrics.JwksFetchTotal.WithLabelValues(uri, "error").Inc()
		return nil, fmt.Errorf("failed to fetch/parse JWKS: %w", err)
	}

	metrics.JwksFetchTotal.WithLabelValues(uri, "success").Inc()
	return set, nil
}

func (c *DefaultClient) GetMetadata(ctx context.Context, uri string) (map[string]interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build metadata request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metadata fetch returned status %d", resp.StatusCode)
	}

	var metadata map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("failed to decode metadata: %w", err)
	}
	return metadata, nil
}

func (c *DefaultClient) Invalidate(uri string) {
	_, _ = c.cache.Refresh(context.Background(), uri)
}
