// Package oauthbridge implements the OAuth 2.0 authorization-code flow used by
// AAuth Mode 2 (resource-managed access). The extauth service acts as the OAuth
// client, redirecting users to an upstream provider and exchanging the auth code
// for tokens that are then wrapped into an opaque AAuth-Access blob.
package oauthbridge

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"aauth-service/internal/config"
)

// AuthorizeURL builds the OAuth 2.0 authorization URL the user's browser is sent to.
// state and pkceChallenge may be empty if PKCE is disabled.
func AuthorizeURL(rc *config.ResourceConfig, state, pkceChallenge string) string {
	b := rc.OAuthBridge
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", b.ClientID)
	params.Set("redirect_uri", RedirectURI(rc))
	params.Set("state", state)
	if len(b.Scopes) > 0 {
		params.Set("scope", strings.Join(b.Scopes, " "))
	}
	if b.Audience != "" {
		params.Set("audience", b.Audience)
	}
	if b.UsePKCE && pkceChallenge != "" {
		params.Set("code_challenge", pkceChallenge)
		params.Set("code_challenge_method", "S256")
	}
	for k, v := range b.ExtraAuthParams {
		params.Set(k, v)
	}
	sep := "?"
	if strings.Contains(b.AuthorizeURL, "?") {
		sep = "&"
	}
	return b.AuthorizeURL + sep + params.Encode()
}

// RedirectURI returns the OAuth redirect_uri for the given resource.
// It is: {RedirectURIBase}/oauth/{resourceID}/callback
func RedirectURI(rc *config.ResourceConfig) string {
	base := strings.TrimRight(rc.OAuthBridge.RedirectURIBase, "/")
	return base + "/oauth/" + rc.ID + "/callback"
}

// tokenResponse is the JSON body from an OAuth token endpoint.
type tokenResponse struct {
	AccessToken           string `json:"access_token"`
	RefreshToken          string `json:"refresh_token"`
	TokenType             string `json:"token_type"`
	ExpiresIn             int    `json:"expires_in"`
	RefreshTokenExpiresIn int    `json:"refresh_token_expires_in,omitempty"`
	Scope                 string `json:"scope"`
	Error                 string `json:"error"`
	ErrorDescription      string `json:"error_description"`
}

// ExchangeCodeResult holds the token returned after a code exchange.
type ExchangeCodeResult struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	ExpiresAt    time.Time // zero if provider does not return expires_in
	Scope        string
}

// ExchangeCode exchanges an OAuth authorization code for tokens.
// pkceVerifier is empty when PKCE is disabled.
func ExchangeCode(ctx context.Context, rc *config.ResourceConfig, code, pkceVerifier string) (*ExchangeCodeResult, error) {
	b := rc.OAuthBridge
	body := url.Values{}
	body.Set("grant_type", "authorization_code")
	body.Set("code", code)
	body.Set("redirect_uri", RedirectURI(rc))
	body.Set("client_id", b.ClientID)
	body.Set("client_secret", b.ClientSecret)
	if b.UsePKCE && pkceVerifier != "" {
		body.Set("code_verifier", pkceVerifier)
	}

	return doTokenRequest(ctx, b.TokenURL, body)
}

// RefreshToken obtains a new access token using a refresh token.
func RefreshToken(ctx context.Context, rc *config.ResourceConfig, refreshToken string) (*ExchangeCodeResult, error) {
	b := rc.OAuthBridge
	body := url.Values{}
	body.Set("grant_type", "refresh_token")
	body.Set("refresh_token", refreshToken)
	body.Set("client_id", b.ClientID)
	body.Set("client_secret", b.ClientSecret)

	return doTokenRequest(ctx, b.TokenURL, body)
}

func doTokenRequest(ctx context.Context, tokenURL string, body url.Values) (*ExchangeCodeResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL,
		strings.NewReader(body.Encode()))
	if err != nil {
		return nil, fmt.Errorf("oauthbridge: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oauthbridge: token request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("oauthbridge: read body: %w", err)
	}

	var tr tokenResponse
	if err := json.Unmarshal(respBody, &tr); err != nil {
		return nil, fmt.Errorf("oauthbridge: unmarshal response (status %d): %w", resp.StatusCode, err)
	}
	if tr.Error != "" {
		return nil, fmt.Errorf("oauthbridge: provider error %q: %s", tr.Error, tr.ErrorDescription)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oauthbridge: unexpected status %d", resp.StatusCode)
	}

	result := &ExchangeCodeResult{
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		TokenType:    tr.TokenType,
		Scope:        tr.Scope,
	}
	if tr.ExpiresIn > 0 {
		result.ExpiresAt = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	}
	return result, nil
}
