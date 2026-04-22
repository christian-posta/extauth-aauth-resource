package aauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

func TestParseAndVerifyAgentTokenRejectsAudienceMismatch(t *testing.T) {
	agentPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverPub, serverPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	serverKey, err := jwk.FromRaw(serverPub)
	if err != nil {
		t.Fatal(err)
	}
	serverKey.Set(jwk.KeyIDKey, "agent-server-key-1")
	set := jwk.NewSet()
	set.AddKey(serverKey)

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
		"dwk": "aauth-agent.json",
		"sub": "aauth:agent@agents.example.com",
		"aud": "https://other-resource.example.com",
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
	sig := ed25519.Sign(serverPriv, []byte(unsignedToken))
	token := unsignedToken + "." + base64.RawURLEncoding.EncodeToString(sig)

	_, err = ParseAndVerifyAgentToken(token, set, "https://resource.example.com")
	if err == nil {
		t.Fatal("expected audience mismatch error")
	}
}
