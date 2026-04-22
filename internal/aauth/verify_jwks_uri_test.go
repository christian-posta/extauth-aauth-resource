package aauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"

	"aauth-service/internal/config"
	"aauth-service/internal/jwksfetch"
	"aauth-service/pkg/httpsig"
	"aauth-service/pkg/httpsig/structfields"
)

func TestVerifyRejectsNonHTTPSJWKSURI(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	sigKeyVal := `sig=jwks_uri;id="http://agents.example.com";dwk="aauth-agent.json";kid="agent-key-1"`
	headers := map[string][]string{
		"signature-key": {sigKeyVal},
	}

	now := time.Now().Unix()
	params := structfields.Params{
		{Name: "created", Value: now},
		{Name: "alg", Value: "ed25519"},
		{Name: "keyid", Value: "agent-key-1"},
	}

	sigBytes, sigInputStr, err := httpsig.Sign(httpsig.SignInput{
		Method:     "GET",
		Authority:  "resource.example.com",
		Path:       "/api",
		Headers:    headers,
		Label:      "sig",
		Components: []string{"@method", "@authority", "@path", "signature-key"},
		Params:     params,
		PrivateKey: priv,
		Alg:        "ed25519",
	})
	if err != nil {
		t.Fatal(err)
	}
	headers["signature-input"] = []string{sigInputStr}
	headers["signature"] = []string{`sig=:` + base64.StdEncoding.EncodeToString(sigBytes) + `:`}

	rc := &config.ResourceConfig{
		Issuer: "https://resource.example.com",
		AgentServers: []config.AgentServer{
			{Issuer: "http://agents.example.com", JwksURI: "http://agents.example.com/jwks.json"},
		},
		SignatureWindow: 60 * time.Second,
	}

	key, err := jwk.FromRaw(pub)
	if err != nil {
		t.Fatal(err)
	}
	key.Set(jwk.KeyIDKey, "agent-key-1")
	set := jwk.NewSet()
	set.AddKey(key)
	mockJwks := jwksfetch.NewMockClient()
	mockJwks.Metadata["http://agents.example.com/.well-known/aauth-agent.json"] = map[string]interface{}{
		"jwks_uri": "http://agents.example.com/jwks.json",
	}
	mockJwks.Keysets["http://agents.example.com/jwks.json"] = set

	result := Verify(rc, "GET", "resource.example.com", "/api", headers, mockJwks)
	if result.Err != ErrInvalidKey {
		t.Fatalf("expected ErrInvalidKey, got %v", result.Err)
	}
}

func TestVerifyRejectsKeyIDMismatchBetweenSignatureKeyAndSignatureInput(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	agentID := "https://agents.example.com"
	dwk := "aauth-agent.json"
	discoveryURL := agentID + "/.well-known/" + dwk
	jwksURI := "https://agents.example.com/jwks.json"
	sigKeyVal := `sig=jwks_uri;id="` + agentID + `";dwk="` + dwk + `";kid="agent-key-1"`
	headers := map[string][]string{
		"signature-key": {sigKeyVal},
	}

	now := time.Now().Unix()
	params := structfields.Params{
		{Name: "created", Value: now},
		{Name: "alg", Value: "ed25519"},
		{Name: "keyid", Value: "different-keyid"},
	}

	sigBytes, sigInputStr, err := httpsig.Sign(httpsig.SignInput{
		Method:     "GET",
		Authority:  "resource.example.com",
		Path:       "/api",
		Headers:    headers,
		Label:      "sig",
		Components: []string{"@method", "@authority", "@path", "signature-key"},
		Params:     params,
		PrivateKey: priv,
		Alg:        "ed25519",
	})
	if err != nil {
		t.Fatal(err)
	}
	headers["signature-input"] = []string{sigInputStr}
	headers["signature"] = []string{`sig=:` + base64.StdEncoding.EncodeToString(sigBytes) + `:`}

	rc := &config.ResourceConfig{
		Issuer: "https://resource.example.com",
		AgentServers: []config.AgentServer{
			{Issuer: "https://agents.example.com", JwksURI: jwksURI},
		},
		SignatureWindow: 60 * time.Second,
	}

	key, err := jwk.FromRaw(pub)
	if err != nil {
		t.Fatal(err)
	}
	key.Set(jwk.KeyIDKey, "agent-key-1")
	set := jwk.NewSet()
	set.AddKey(key)
	mockJwks := jwksfetch.NewMockClient()
	mockJwks.Metadata[discoveryURL] = map[string]interface{}{
		"jwks_uri": jwksURI,
	}
	mockJwks.Keysets[jwksURI] = set

	result := Verify(rc, "GET", "resource.example.com", "/api", headers, mockJwks)
	if result.Err != ErrInvalidSignature {
		t.Fatalf("expected ErrInvalidSignature, got %v", result.Err)
	}
}

func TestVerifyRefreshesJWKSOnceBeforeReturningUnknownKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	agentID := "https://agents.example.com"
	dwk := "aauth-agent.json"
	discoveryURL := agentID + "/.well-known/" + dwk
	jwksURI := "https://agents.example.com/jwks.json"
	sigKeyVal := `sig=jwks_uri;id="` + agentID + `";dwk="` + dwk + `";kid="rotated-key"`
	headers := map[string][]string{
		"signature-key": {sigKeyVal},
	}

	now := time.Now().Unix()
	params := structfields.Params{
		{Name: "created", Value: now},
		{Name: "alg", Value: "ed25519"},
		{Name: "keyid", Value: "rotated-key"},
	}

	sigBytes, sigInputStr, err := httpsig.Sign(httpsig.SignInput{
		Method:     "GET",
		Authority:  "resource.example.com",
		Path:       "/api",
		Headers:    headers,
		Label:      "sig",
		Components: []string{"@method", "@authority", "@path", "signature-key"},
		Params:     params,
		PrivateKey: priv,
		Alg:        "ed25519",
	})
	if err != nil {
		t.Fatal(err)
	}
	headers["signature-input"] = []string{sigInputStr}
	headers["signature"] = []string{`sig=:` + base64.StdEncoding.EncodeToString(sigBytes) + `:`}

	rc := &config.ResourceConfig{
		Issuer: "https://resource.example.com",
		AgentServers: []config.AgentServer{
			{Issuer: "https://agents.example.com", JwksURI: jwksURI},
		},
		SignatureWindow: 60 * time.Second,
	}

	initialPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	initialKey, err := jwk.FromRaw(initialPub)
	if err != nil {
		t.Fatal(err)
	}
	initialKey.Set(jwk.KeyIDKey, "stale-key")
	initialSet := jwk.NewSet()
	initialSet.AddKey(initialKey)

	rotatedKey, err := jwk.FromRaw(pub)
	if err != nil {
		t.Fatal(err)
	}
	rotatedKey.Set(jwk.KeyIDKey, "rotated-key")
	refreshedSet := jwk.NewSet()
	refreshedSet.AddKey(rotatedKey)

	mockJwks := jwksfetch.NewMockClient()
	mockJwks.Metadata[discoveryURL] = map[string]interface{}{
		"jwks_uri": jwksURI,
	}
	mockJwks.Keysets[jwksURI] = initialSet
	mockJwks.OnInvalidate = func(uri string) {
		mockJwks.Keysets[uri] = refreshedSet
	}

	result := Verify(rc, "GET", "resource.example.com", "/api", headers, mockJwks)
	if result.Err != nil {
		b, _ := json.Marshal(result.Diagnostics)
		t.Fatalf("expected success after refresh, got err=%v diagnostics=%s", result.Err, string(b))
	}
	if mockJwks.InvalidateCalls[jwksURI] != 1 {
		t.Fatalf("expected exactly one invalidate call, got %d", mockJwks.InvalidateCalls[jwksURI])
	}
	if mockJwks.GetCalls[jwksURI] < 2 {
		t.Fatalf("expected at least two jwks fetches, got %d", mockJwks.GetCalls[jwksURI])
	}
}
