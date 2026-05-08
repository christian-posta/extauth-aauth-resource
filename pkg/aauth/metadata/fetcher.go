package metadata

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"aauth-service/pkg/aauth/identifiers"
)

type FetcherOptions struct {
	HTTPClient *http.Client
	Logger     *slog.Logger
}

type Fetcher struct {
	client *http.Client
	logger *slog.Logger
}

func NewFetcher(opts FetcherOptions) *Fetcher {
	client := opts.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Fetcher{client: client, logger: logger}
}

func (f *Fetcher) FetchResource(ctx context.Context, resourceID string) (*ResourceMetadata, error) {
	url, err := buildWellKnownURL(resourceID, "aauth-resource.json")
	if err != nil {
		return nil, err
	}
	var m ResourceMetadata
	if err := f.fetchJSON(ctx, url, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func (f *Fetcher) FetchPersonServer(ctx context.Context, psID string) (*PersonServerMetadata, error) {
	url, err := buildWellKnownURL(psID, "aauth-person.json")
	if err != nil {
		return nil, err
	}
	var m PersonServerMetadata
	if err := f.fetchJSON(ctx, url, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func (f *Fetcher) FetchAuthServer(ctx context.Context, authServerID string) (*AuthServerMetadata, error) {
	url, err := buildWellKnownURL(authServerID, "aauth-access.json")
	if err != nil {
		return nil, err
	}
	var m AuthServerMetadata
	if err := f.fetchJSON(ctx, url, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func (f *Fetcher) FetchAgentServer(ctx context.Context, agentServerID string) (*AgentServerMetadata, error) {
	url, err := buildWellKnownURL(agentServerID, "aauth-agent.json")
	if err != nil {
		return nil, err
	}
	var m AgentServerMetadata
	if err := f.fetchJSON(ctx, url, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func (f *Fetcher) fetchJSON(ctx context.Context, url string, dst interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("metadata: build request for %s: %w", url, err)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return fmt.Errorf("metadata: fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("metadata: %s returned status %d", url, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		return fmt.Errorf("metadata: decode response from %s: %w", url, err)
	}
	return nil
}

func buildWellKnownURL(serverID, filename string) (string, error) {
	if isLocalhostHTTP(serverID) {
		base := strings.TrimRight(serverID, "/")
		return base + "/.well-known/" + filename, nil
	}
	if err := identifiers.ValidateServerIdentifier(serverID); err != nil {
		return "", fmt.Errorf("metadata: invalid server identifier %q: %w", serverID, err)
	}
	return serverID + "/.well-known/" + filename, nil
}

func isLocalhostHTTP(s string) bool {
	if !strings.HasPrefix(s, "http://") {
		return false
	}
	rest := s[len("http://"):]
	host := rest
	if idx := strings.IndexByte(rest, '/'); idx >= 0 {
		host = rest[:idx]
	}
	if idx := strings.LastIndexByte(host, ':'); idx >= 0 {
		host = host[:idx]
	}
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
