package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"aauth-service/pkg/httpsig"
	"aauth-service/pkg/sigkey"
)

func generateTestKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	return pub, priv
}

func newTestSigner(t *testing.T, tokens *TokenStore) (*RequestSigner, ed25519.PublicKey) {
	t.Helper()
	pub, priv := generateTestKey(t)
	s, err := NewRequestSigner(SignerOptions{
		AgentID:   "aauth:agent@example.com",
		KeyID:     "key-1",
		Signer:    priv,
		Algorithm: "ed25519",
		Tokens:    tokens,
		Clock:     func() time.Time { return time.Now() },
	})
	if err != nil {
		t.Fatalf("NewRequestSigner: %v", err)
	}
	return s, pub
}

func TestNewRequestSigner_Validation(t *testing.T) {
	_, priv := generateTestKey(t)

	tests := []struct {
		name    string
		opts    SignerOptions
		wantErr bool
	}{
		{
			name: "valid",
			opts: SignerOptions{
				AgentID:   "aauth:agent@example.com",
				KeyID:     "k1",
				Signer:    priv,
				Algorithm: "ed25519",
			},
			wantErr: false,
		},
		{
			name: "missing AgentID",
			opts: SignerOptions{
				KeyID:     "k1",
				Signer:    priv,
				Algorithm: "ed25519",
			},
			wantErr: true,
		},
		{
			name: "invalid AgentID",
			opts: SignerOptions{
				AgentID:   "not-an-agent-id",
				KeyID:     "k1",
				Signer:    priv,
				Algorithm: "ed25519",
			},
			wantErr: true,
		},
		{
			name: "missing KeyID",
			opts: SignerOptions{
				AgentID:   "aauth:agent@example.com",
				Signer:    priv,
				Algorithm: "ed25519",
			},
			wantErr: true,
		},
		{
			name: "missing Signer",
			opts: SignerOptions{
				AgentID:   "aauth:agent@example.com",
				KeyID:     "k1",
				Algorithm: "ed25519",
			},
			wantErr: true,
		},
		{
			name: "missing Algorithm",
			opts: SignerOptions{
				AgentID: "aauth:agent@example.com",
				KeyID:   "k1",
				Signer:  priv,
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewRequestSigner(tc.opts)
			if (err != nil) != tc.wantErr {
				t.Errorf("NewRequestSigner error=%v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestSign_HWKScheme(t *testing.T) {
	s, pub := newTestSigner(t, nil)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/foo", nil)
	comps := []string{"@method", "@authority", "@path", "signature-key"}

	if err := s.Sign(context.Background(), req, comps); err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	sigHdr := req.Header.Get("signature")
	sigInputHdr := req.Header.Get("signature-input")
	sigKeyHdr := req.Header.Get("signature-key")

	if sigHdr == "" {
		t.Error("missing Signature header")
	}
	if sigInputHdr == "" {
		t.Error("missing Signature-Input header")
	}
	if sigKeyHdr == "" {
		t.Error("missing Signature-Key header")
	}

	if !strings.HasPrefix(sigKeyHdr, "sig=hwk;") {
		t.Errorf("expected hwk scheme in Signature-Key, got: %s", sigKeyHdr)
	}

	result, err := httpsig.Verify(httpsig.VerifyInput{
		Method:    req.Method,
		Authority: req.URL.Host,
		Path:      req.URL.RequestURI(),
		Headers: map[string][]string{
			"signature":       {sigHdr},
			"signature-input": {sigInputHdr},
			"signature-key":   {sigKeyHdr},
		},
		Label:              "sig",
		RequiredComponents: []string{"@method", "@authority", "@path", "signature-key"},
		AllowedAlgs:        []string{"ed25519"},
		MaxClockSkew:       60 * time.Second,
		PublicKey:          pub,
		Alg:                "ed25519",
	})
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if result.Label != "sig" {
		t.Errorf("unexpected label: %s", result.Label)
	}
}

func TestSign_JWTScheme(t *testing.T) {
	fakeJWT := "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ0ZXN0In0.fake"
	s, pub := newTestSigner(t, &TokenStore{
		AgentToken: fakeJWT,
	})

	if got := s.Scheme(); got != "jwt" {
		t.Errorf("expected jwt scheme, got %s", got)
	}

	req := httptest.NewRequest(http.MethodPost, "http://example.com/api", nil)
	comps := []string{"@method", "@authority", "@path", "signature-key"}

	if err := s.Sign(context.Background(), req, comps); err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	sigKeyHdr := req.Header.Get("signature-key")
	if !strings.HasPrefix(sigKeyHdr, "sig=jwt;") {
		t.Errorf("expected jwt scheme in Signature-Key, got: %s", sigKeyHdr)
	}
	if !strings.Contains(sigKeyHdr, fakeJWT) {
		t.Errorf("Signature-Key missing JWT value, got: %s", sigKeyHdr)
	}

	sigHdr := req.Header.Get("signature")
	sigInputHdr := req.Header.Get("signature-input")

	_, err := httpsig.Verify(httpsig.VerifyInput{
		Method:    req.Method,
		Authority: req.URL.Host,
		Path:      req.URL.RequestURI(),
		Headers: map[string][]string{
			"signature":       {sigHdr},
			"signature-input": {sigInputHdr},
			"signature-key":   {sigKeyHdr},
		},
		Label:              "sig",
		RequiredComponents: []string{"@method", "@authority", "@path", "signature-key"},
		AllowedAlgs:        []string{"ed25519"},
		MaxClockSkew:       60 * time.Second,
		PublicKey:          pub,
		Alg:                "ed25519",
	})
	if err != nil {
		t.Fatalf("Verify (jwt scheme) failed: %v", err)
	}
}

func TestSign_AuthTokenHeader(t *testing.T) {
	authTok := "eyJhbGciOiJFZERTQSJ9.auth.tok"
	s, _ := newTestSigner(t, &TokenStore{
		AuthToken: authTok,
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	if err := s.Sign(context.Background(), req, []string{"@method", "@path", "signature-key"}); err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if got := req.Header.Get("AAuth-Token"); got != authTok {
		t.Errorf("AAuth-Token header: got %q, want %q", got, authTok)
	}
}

func TestScheme_Default(t *testing.T) {
	s, _ := newTestSigner(t, nil)
	if s.Scheme() != "hwk" {
		t.Errorf("expected hwk, got %s", s.Scheme())
	}
}

func TestSign_JWKSURIScheme(t *testing.T) {
	_, priv := generateTestKey(t)
	s, err := NewRequestSigner(SignerOptions{
		AgentID:     "aauth:agent@example.com",
		KeyID:       "key-1",
		Signer:      priv,
		Algorithm:   "ed25519",
		DiscoveryID: "aauth:agent@example.com",
	})
	if err != nil {
		t.Fatalf("NewRequestSigner: %v", err)
	}
	if got := s.Scheme(); got != "jwks_uri" {
		t.Errorf("expected jwks_uri scheme, got %s", got)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/foo", nil)
	if err := s.Sign(context.Background(), req, []string{"@method", "@authority", "@path", "signature-key"}); err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	sigKeyHdr := req.Header.Get("signature-key")
	if !strings.HasPrefix(sigKeyHdr, "sig=jwks_uri;") {
		t.Errorf("expected jwks_uri scheme in Signature-Key, got: %s", sigKeyHdr)
	}
	parsed, err := sigkey.Parse(sigKeyHdr)
	if err != nil {
		t.Fatalf("sigkey.Parse failed: %v", err)
	}
	if parsed.Scheme != sigkey.SchemeJWKSURI {
		t.Errorf("parsed scheme = %v, want jwks_uri", parsed.Scheme)
	}
	if parsed.ID != "aauth:agent@example.com" {
		t.Errorf("parsed id = %q", parsed.ID)
	}
	if parsed.DWK != "aauth-agent.json" {
		t.Errorf("parsed dwk = %q", parsed.DWK)
	}
	if parsed.KeyID != "key-1" {
		t.Errorf("parsed kid = %q", parsed.KeyID)
	}
}

func TestSignatureKey_AllSchemesParseRoundTrip(t *testing.T) {
	_, priv := generateTestKey(t)

	cases := []struct {
		name     string
		opts     SignerOptions
		wantSch  sigkey.Scheme
		checkers func(t *testing.T, p sigkey.Parsed)
	}{
		{
			name: "hwk",
			opts: SignerOptions{
				AgentID:   "aauth:agent@example.com",
				KeyID:     "key-1",
				Signer:    priv,
				Algorithm: "ed25519",
			},
			wantSch: sigkey.SchemeHWK,
			checkers: func(t *testing.T, p sigkey.Parsed) {
				if p.HWK["kty"] != "OKP" || p.HWK["crv"] != "Ed25519" {
					t.Errorf("hwk JWK params unexpected: %+v", p.HWK)
				}
			},
		},
		{
			name: "jwt",
			opts: SignerOptions{
				AgentID:   "aauth:agent@example.com",
				KeyID:     "key-1",
				Signer:    priv,
				Algorithm: "ed25519",
				Tokens:    &TokenStore{AgentToken: "eyJhbGciOiJFZERTQSJ9.test.sig"},
			},
			wantSch: sigkey.SchemeJWT,
			checkers: func(t *testing.T, p sigkey.Parsed) {
				if p.JWT != "eyJhbGciOiJFZERTQSJ9.test.sig" {
					t.Errorf("jwt = %q", p.JWT)
				}
			},
		},
		{
			name: "jwks_uri",
			opts: SignerOptions{
				AgentID:     "aauth:agent@example.com",
				KeyID:       "key-1",
				Signer:      priv,
				Algorithm:   "ed25519",
				DiscoveryID: "aauth:agent@example.com",
			},
			wantSch: sigkey.SchemeJWKSURI,
			checkers: func(t *testing.T, p sigkey.Parsed) {
				if p.ID != "aauth:agent@example.com" || p.DWK != "aauth-agent.json" || p.KeyID != "key-1" {
					t.Errorf("jwks_uri parsed = %+v", p)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := NewRequestSigner(tc.opts)
			if err != nil {
				t.Fatalf("NewRequestSigner: %v", err)
			}
			req := httptest.NewRequest(http.MethodGet, "http://example.com/x", nil)
			if err := s.Sign(context.Background(), req, []string{"@method", "@authority", "@path", "signature-key"}); err != nil {
				t.Fatalf("Sign: %v", err)
			}
			hdr := req.Header.Get("signature-key")
			parsed, err := sigkey.Parse(hdr)
			if err != nil {
				t.Fatalf("Parse(%q): %v", hdr, err)
			}
			if parsed.Scheme != tc.wantSch {
				t.Errorf("scheme = %v, want %v", parsed.Scheme, tc.wantSch)
			}
			if tc.checkers != nil {
				tc.checkers(t, parsed)
			}
		})
	}
}

