package agent

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"aauth-service/pkg/aauth/identifiers"
	"aauth-service/pkg/httpsig"
	"aauth-service/pkg/httpsig/structfields"
)

// Algorithm is the name of a supported HTTP message signature algorithm (e.g. "ed25519").
type Algorithm = string

// TokenStore holds tokens an agent may present.
type TokenStore struct {
	AgentToken    string
	ResourceToken string
	AuthToken     string
}

// SignerOptions configures a RequestSigner.
type SignerOptions struct {
	AgentID   string
	KeyID     string
	Signer    crypto.Signer
	Algorithm Algorithm
	Tokens    *TokenStore
	Clock     func() time.Time
	Logger    *slog.Logger
	// DiscoveryID is the agent's HTTPS identifier; when non-empty (and no
	// AgentToken is present) the signer emits the jwks_uri scheme so verifiers
	// can fetch the JWKS from the agent's well-known metadata.
	DiscoveryID string
	// DWK is the well-known document name advertised in the jwks_uri scheme.
	// Defaults to "aauth-agent.json" when empty.
	DWK string
}

// RequestSigner signs outgoing HTTP requests on behalf of an agent.
type RequestSigner struct {
	agentID     string
	keyID       string
	signer      crypto.Signer
	algorithm   Algorithm
	tokens      *TokenStore
	clock       func() time.Time
	logger      *slog.Logger
	discoveryID string
	dwk         string
}

// NewRequestSigner validates opts and returns a RequestSigner.
func NewRequestSigner(opts SignerOptions) (*RequestSigner, error) {
	if err := identifiers.ValidateAgentIdentifier(opts.AgentID); err != nil {
		return nil, fmt.Errorf("agent/signer: invalid AgentID: %w", err)
	}
	if opts.KeyID == "" {
		return nil, errors.New("agent/signer: KeyID must not be empty")
	}
	if opts.Signer == nil {
		return nil, errors.New("agent/signer: Signer must not be nil")
	}
	if opts.Algorithm == "" {
		return nil, errors.New("agent/signer: Algorithm must not be empty")
	}

	clock := opts.Clock
	if clock == nil {
		clock = time.Now
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	tokens := opts.Tokens
	if tokens == nil {
		tokens = &TokenStore{}
	}

	dwk := opts.DWK
	if dwk == "" {
		dwk = "aauth-agent.json"
	}

	return &RequestSigner{
		agentID:     opts.AgentID,
		keyID:       opts.KeyID,
		signer:      opts.Signer,
		algorithm:   opts.Algorithm,
		tokens:      tokens,
		clock:       clock,
		logger:      logger,
		discoveryID: opts.DiscoveryID,
		dwk:         dwk,
	}, nil
}

// Scheme returns the Signature-Key scheme this signer will use given the current token state.
func (s *RequestSigner) Scheme() string {
	if s.tokens.AgentToken != "" {
		return "jwt"
	}
	if s.discoveryID != "" {
		return "jwks_uri"
	}
	return "hwk"
}

// Sign adds Signature, Signature-Input, and Signature-Key headers to req.
func (s *RequestSigner) Sign(ctx context.Context, req *http.Request, comps []string) error {
	if s.tokens.AuthToken != "" {
		req.Header.Set("AAuth-Token", s.tokens.AuthToken)
	}

	sigKeyVal, err := s.buildSignatureKeyHeader()
	if err != nil {
		return fmt.Errorf("agent/signer: build signature-key header: %w", err)
	}
	req.Header.Set("signature-key", sigKeyVal)

	authority := req.Host
	if authority == "" && req.URL != nil {
		authority = req.URL.Host
	}
	path := "/"
	if req.URL != nil {
		path = req.URL.RequestURI()
		if path == "" {
			path = "/"
		}
	}

	headers := make(map[string][]string)
	for k, v := range req.Header {
		headers[strings.ToLower(k)] = v
	}

	params := structfields.Params{
		{Name: "created", Value: s.clock().Unix()},
		{Name: "alg", Value: s.algorithm},
		{Name: "keyid", Value: s.keyID},
	}

	signInput := httpsig.SignInput{
		Method:     req.Method,
		Authority:  authority,
		Path:       path,
		Headers:    headers,
		Label:      "sig",
		Components: comps,
		Params:     params,
		PrivateKey: s.signer,
		Alg:        s.algorithm,
	}

	sigBytes, sigInputStr, err := httpsig.Sign(signInput)
	if err != nil {
		return fmt.Errorf("agent/signer: sign: %w", err)
	}

	req.Header.Set("signature-input", sigInputStr)
	req.Header.Set("signature", "sig=:"+base64.StdEncoding.EncodeToString(sigBytes)+":")

	s.logger.DebugContext(ctx, "request signed",
		"agent_id", s.agentID,
		"scheme", s.Scheme(),
		"components", comps,
	)
	return nil
}

// buildSignatureKeyHeader constructs the Signature-Key header value for the current token state.
func (s *RequestSigner) buildSignatureKeyHeader() (string, error) {
	scheme := s.Scheme()

	switch scheme {
	case "jwt":
		// sig=jwt;jwt="<token>"
		return fmt.Sprintf(`sig=jwt;jwt=%q`, s.tokens.AgentToken), nil

	case "jwks_uri":
		return fmt.Sprintf(`sig=jwks_uri;id=%q;dwk=%q;kid=%q`, s.discoveryID, s.dwk, s.keyID), nil

	case "hwk":
		// Extract the public key and encode as JWK fields inline.
		pub := s.signer.Public()
		edPub, ok := pub.(ed25519.PublicKey)
		if !ok {
			return "", fmt.Errorf("hwk scheme requires an ed25519.PublicKey, got %T", pub)
		}
		x64 := base64.RawURLEncoding.EncodeToString(edPub)
		return fmt.Sprintf(`sig=hwk;kty="OKP";crv="Ed25519";x=%q`, x64), nil

	default:
		return "", fmt.Errorf("unsupported scheme: %q", scheme)
	}
}
