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

func TestVerifyDisallowedSignatureKeySchemeHWK(t *testing.T) {
	x64 := base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))
	headers := map[string][]string{
		"signature-key":   {`sig=hwk;kty="OKP";crv="Ed25519";x="` + x64 + `"`},
		"signature-input": {`sig=("@method" "@authority" "@path" "signature-key");created=1;alg="ed25519"`},
		"signature":       {`sig=:AQID:`},
	}
	rc := &config.ResourceConfig{
		Issuer:                     "https://resource.example.com",
		AllowPseudonymous:          true,
		SignatureWindow:            60 * time.Second,
		AllowedSignatureKeySchemes: []string{config.SchemeJWT},
	}
	res := Verify(rc, "GET", "resource.example.com", "/api", headers, nil)
	if res.Err != ErrDisallowedSignatureKeyScheme {
		t.Fatalf("expected ErrDisallowedSignatureKeyScheme, got %v", res.Err)
	}
}

func TestVerifyDisallowedJWTTypWhenOnlyAuthAllowed(t *testing.T) {
	agentPub, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, agentServerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	mockJwks := jwksfetch.NewMockClient()

	agentKeyJWK, _ := jwk.FromRaw(agentPub)
	jwkBytes, _ := json.Marshal(agentKeyJWK)
	var jwkMap map[string]interface{}
	_ = json.Unmarshal(jwkBytes, &jwkMap)

	claims := map[string]interface{}{
		"iss": "https://agents.example.com",
		"dwk": "aauth-agent.json",
		"sub": "test-delegate",
		"aud": "https://res.example.com",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"cnf": map[string]interface{}{
			"jwk": jwkMap,
		},
	}

	header := map[string]interface{}{
		"typ": "aa-agent+jwt",
		"alg": "EdDSA",
		"kid": "as-key-1",
	}

	headerBytes, _ := json.Marshal(header)
	claimsBytes, _ := json.Marshal(claims)
	unsignedToken := base64.RawURLEncoding.EncodeToString(headerBytes) + "." + base64.RawURLEncoding.EncodeToString(claimsBytes)
	sig := ed25519.Sign(agentServerPriv, []byte(unsignedToken))
	tokenStr := unsignedToken + "." + base64.RawURLEncoding.EncodeToString(sig)

	sigKeyVal := `sig=jwt;jwt="` + tokenStr + `"`
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
		Authority:  "res.example.com",
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
		Issuer: "https://res.example.com",
		AgentServers: []config.AgentServer{
			{Issuer: "https://agents.example.com", JwksURI: "https://agents.example.com/jwks.json"},
		},
		SignatureWindow:            60 * time.Second,
		AllowedJWTTypes:            []string{config.JWTTypeAuth},
		AllowedSignatureKeySchemes: []string{config.SchemeJWT},
	}

	res := Verify(rc, "GET", "res.example.com", "/api", headers, mockJwks)
	if res.Err != ErrDisallowedJWTType {
		t.Fatalf("expected ErrDisallowedJWTType, got %v (diag=%+v)", res.Err, res.Diagnostics)
	}
}
