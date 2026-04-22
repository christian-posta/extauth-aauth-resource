package aauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"

	"policy_engine/internal/config"
	"policy_engine/internal/jwksfetch"
	"policy_engine/pkg/httpsig"
	"policy_engine/pkg/httpsig/structfields"
)

func TestVerifyRejectsUnexpectedAgentDwkBeforeJWKSFetch(t *testing.T) {
	agentPub, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, agentServerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	agentKeyJWK, err := jwk.FromRaw(agentPub)
	if err != nil {
		t.Fatal(err)
	}
	jwkBytes, err := json.Marshal(agentKeyJWK)
	if err != nil {
		t.Fatal(err)
	}

	var jwkMap map[string]interface{}
	if err := json.Unmarshal(jwkBytes, &jwkMap); err != nil {
		t.Fatal(err)
	}

	claims := map[string]interface{}{
		"iss": "https://agents.example.com",
		"dwk": "evil.json",
		"sub": "aauth:agent@agents.example.com",
		"aud": "https://resource.example.com",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"cnf": map[string]interface{}{
			"jwk": jwkMap,
		},
	}
	header := map[string]interface{}{
		"typ": "aa-agent+jwt",
		"alg": "EdDSA",
		"kid": "agent-server-key-1",
	}

	headerBytes, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}

	unsignedToken := base64.RawURLEncoding.EncodeToString(headerBytes) + "." + base64.RawURLEncoding.EncodeToString(claimsBytes)
	sig := ed25519.Sign(agentServerPriv, []byte(unsignedToken))
	token := unsignedToken + "." + base64.RawURLEncoding.EncodeToString(sig)

	sigKeyVal := `sig=jwt;jwt="` + token + `"`
	headers := map[string][]string{
		"signature-key": {sigKeyVal},
	}

	now := time.Now().Unix()
	params := structfields.Params{
		{Name: "created", Value: now},
		{Name: "alg", Value: "ed25519"},
	}

	sigBytes, sigInputStr, err := httpsig.Sign(httpsig.SignInput{
		Method:     "GET",
		Authority:  "resource.example.com",
		Path:       "/api",
		Headers:    headers,
		Label:      "sig",
		Components: []string{"@method", "@authority", "@path", "signature-key"},
		Params:     params,
		PrivateKey: agentPriv,
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
			{Issuer: "https://agents.example.com", JwksURI: "https://agents.example.com/jwks.json"},
		},
		SignatureWindow: 60 * time.Second,
	}

	mockJwks := jwksfetch.NewMockClient()
	result := Verify(rc, "GET", "resource.example.com", "/api", headers, mockJwks)
	if result.Err != ErrInvalidJWT {
		t.Fatalf("expected ErrInvalidJWT, got %v", result.Err)
	}
	if len(mockJwks.Keysets) != 0 {
		t.Fatalf("expected no JWKS lookups to be configured or used")
	}
}
