package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"

	"aauth-service/pkg/aauth/metadata"
)

// ExchangeRequest carries the inputs for a resource-token exchange.
type ExchangeRequest struct {
	ResourceToken string
	Signer        *RequestSigner
	Scopes        []string
}

// ExchangeResult holds the auth token obtained from the Person Server.
type ExchangeResult struct {
	AuthToken string
	ExpiresAt time.Time
}

// ExchangerOptions configures a TokenExchanger.
type ExchangerOptions struct {
	HTTPClient    *http.Client
	PSMetadataURL string
	Poller        *Poller
	Logger        *slog.Logger
}

// TokenExchanger sends a resource token to a PS token_endpoint and handles
// both immediate (200) and deferred (202) responses.
type TokenExchanger struct {
	client        *http.Client
	psMetadataURL string
	poller        *Poller
	logger        *slog.Logger
}

// NewTokenExchanger validates opts and returns a TokenExchanger.
func NewTokenExchanger(opts ExchangerOptions) (*TokenExchanger, error) {
	client := opts.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &TokenExchanger{
		client:        client,
		psMetadataURL: opts.PSMetadataURL,
		poller:        opts.Poller,
		logger:        logger,
	}, nil
}

// Exchange sends req.ResourceToken to the PS token_endpoint.
// A 200 response returns the auth token immediately.
// A 202 response hands off to the configured Poller.
func (x *TokenExchanger) Exchange(ctx context.Context, req ExchangeRequest) (*ExchangeResult, error) {
	tokenEndpoint, err := x.resolveTokenEndpoint(ctx, req.ResourceToken)
	if err != nil {
		return nil, fmt.Errorf("exchanger: resolve token endpoint: %w", err)
	}

	x.logger.DebugContext(ctx, "exchanging resource token", "endpoint", tokenEndpoint)

	bodyMap := map[string]string{
		"resource_token": req.ResourceToken,
	}
	if len(req.Scopes) > 0 {
		bodyMap["scope"] = strings.Join(req.Scopes, " ")
	}

	bodyBytes, err := json.Marshal(bodyMap)
	if err != nil {
		return nil, fmt.Errorf("exchanger: marshal body: %w", err)
	}

	postReq, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("exchanger: build request: %w", err)
	}
	postReq.Header.Set("Content-Type", "application/json")

	// RFC 9530 Content-Digest: sha-256=:<base64url>:
	digest := sha256.Sum256(bodyBytes)
	digestVal := "sha-256=:" + base64.StdEncoding.EncodeToString(digest[:]) + ":"
	postReq.Header.Set("Content-Digest", digestVal)

	if req.Signer != nil {
		comps := []string{"@method", "@authority", "@path", "content-type", "content-digest"}
		if err := req.Signer.Sign(ctx, postReq, comps); err != nil {
			return nil, fmt.Errorf("exchanger: sign request: %w", err)
		}
	}

	resp, err := x.client.Do(postReq)
	if err != nil {
		return nil, fmt.Errorf("exchanger: POST token_endpoint: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("exchanger: read response: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		return x.parseAuthToken(respBody)

	case http.StatusAccepted:
		location := resp.Header.Get("Location")
		if location == "" {
			return nil, fmt.Errorf("exchanger: 202 response missing Location header")
		}
		if x.poller == nil {
			return nil, fmt.Errorf("exchanger: 202 response but no Poller configured")
		}
		pollResult, err := x.poller.Poll(ctx, location)
		if err != nil {
			return nil, fmt.Errorf("exchanger: polling failed: %w", err)
		}
		if !pollResult.Success {
			return nil, fmt.Errorf("exchanger: exchange denied: %s", pollResult.Error)
		}
		return &ExchangeResult{AuthToken: pollResult.AuthToken}, nil

	default:
		return nil, fmt.Errorf("exchanger: unexpected status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
}

// resolveTokenEndpoint finds the PS token_endpoint.
// If PSMetadataURL is set, it fetches that URL directly (as a raw JSON endpoint).
// Otherwise it parses the resource token JWT (without re-verifying the signature)
// to extract the aud claim, then fetches <aud>/.well-known/aauth-person.json via
// the metadata fetcher.
func (x *TokenExchanger) resolveTokenEndpoint(ctx context.Context, resourceToken string) (string, error) {
	if x.psMetadataURL != "" {
		return x.resolveTokenEndpointFromURL(ctx, x.psMetadataURL)
	}

	psBase, err := extractAudFromToken(resourceToken)
	if err != nil {
		return "", fmt.Errorf("extract aud from resource token: %w", err)
	}

	fetcher := metadata.NewFetcher(metadata.FetcherOptions{
		HTTPClient: x.client,
		Logger:     x.logger,
	})
	psMeta, err := fetcher.FetchPersonServer(ctx, strings.TrimRight(psBase, "/"))
	if err != nil {
		return "", fmt.Errorf("fetch PS metadata: %w", err)
	}
	if psMeta.TokenEndpoint == "" {
		return "", fmt.Errorf("PS metadata missing token_endpoint")
	}
	return psMeta.TokenEndpoint, nil
}

// resolveTokenEndpointFromURL fetches a PS metadata document from an explicit URL.
func (x *TokenExchanger) resolveTokenEndpointFromURL(ctx context.Context, metadataURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := x.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch PS metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("PS metadata returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var meta struct {
		TokenEndpoint string `json:"token_endpoint"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return "", fmt.Errorf("decode PS metadata: %w", err)
	}
	if meta.TokenEndpoint == "" {
		return "", fmt.Errorf("PS metadata missing token_endpoint")
	}
	return meta.TokenEndpoint, nil
}

// extractAudFromToken parses the JWT payload without verifying the signature to
// extract the aud claim. The token is already trusted (received from the resource).
func extractAudFromToken(token string) (string, error) {
	parsed, err := jwt.ParseInsecure([]byte(token))
	if err != nil {
		return "", fmt.Errorf("parse resource token: %w", err)
	}
	auds := parsed.Audience()
	if len(auds) == 0 {
		return "", fmt.Errorf("resource token missing aud claim")
	}
	return auds[0], nil
}

// parseAuthToken extracts the auth token from a 200 response body.
func (x *TokenExchanger) parseAuthToken(body []byte) (*ExchangeResult, error) {
	var resp struct {
		AuthToken   string `json:"auth_token"`
		AccessToken string `json:"access_token"`
		Token       string `json:"token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("exchanger: parse token response: %w", err)
	}
	token := resp.AuthToken
	if token == "" {
		token = resp.AccessToken
	}
	if token == "" {
		token = resp.Token
	}
	if token == "" {
		return nil, fmt.Errorf("exchanger: no auth token in response")
	}
	result := &ExchangeResult{AuthToken: token}
	if resp.ExpiresIn > 0 {
		result.ExpiresAt = time.Now().Add(time.Duration(resp.ExpiresIn) * time.Second)
	}
	return result, nil
}
