package extauthz_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"

	pb "policy_engine/gen/proto"
	"policy_engine/internal/config"
	"policy_engine/internal/extauthz"
	"policy_engine/internal/jwksfetch"
	"policy_engine/internal/policy"
	"policy_engine/internal/resource"
	"policy_engine/pkg/httpsig"
	"policy_engine/pkg/httpsig/structfields"
)

func TestHandlerAgentJWT(t *testing.T) {
	// 1. Generate keys
	agentPub, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	agentServerPub, agentServerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// 2. Setup mock JWKS client
	jwksURI := "https://agents.example.com/jwks.json"

	agentServerKey, err := jwk.FromRaw(agentServerPub)
	if err != nil {
		t.Fatal(err)
	}
	agentServerKey.Set(jwk.KeyIDKey, "as-key-1")

	mockJwks := jwksfetch.NewMockClient()
	set := jwk.NewSet()
	set.AddKey(agentServerKey)
	// AAuth spec discovery URL: {iss}/.well-known/aauth-agent.json
	mockJwks.Keysets["https://agents.example.com/.well-known/aauth-agent.json"] = set

	// 3. Setup Config and Handler
	cfg := &config.Config{}
	cfg.Resources = []config.ResourceConfigYAML{
		{
			ID:     "res-jwt",
			Issuer: "https://res.example.com",
			Hosts:  []string{"res.example.com"},
			AgentServers: []config.AgentServerYAML{
				{Issuer: "https://agents.example.com", JwksURI: jwksURI},
			},
			SignatureWindow: 60 * time.Second,
		},
	}

	reg, _ := resource.NewRegistry(cfg)
	engine := policy.NewDefaultEngine()
	aauthHandler := extauthz.NewAAuthHandler(engine, mockJwks)

	h := extauthz.NewTestHandler(reg, aauthHandler)

	// 4. Create the agent+jwt token
	agentKeyJWK, _ := jwk.FromRaw(agentPub)
	jwkBytes, _ := json.Marshal(agentKeyJWK)
	var jwkMap map[string]interface{}
	json.Unmarshal(jwkBytes, &jwkMap)

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

	// 5. Build Signature-Key header
	sigKeyVal := `sig=jwt;jwt="` + tokenStr + `"`

	// 6. Build HTTP Signature
	headers := map[string][]string{
		"signature-key": {sigKeyVal},
	}

	now := time.Now().Unix()
	params := structfields.Params{
		{Name: "created", Value: now},
		{Name: "alg", Value: "ed25519"},
	}

	signInput := httpsig.SignInput{
		Method:     "GET",
		Authority:  "res.example.com",
		Path:       "/api",
		Headers:    headers,
		Label:      "sig",
		Components: []string{"@method", "@authority", "@path", "signature-key"},
		Params:     params,
		PrivateKey: agentPriv, // Signed by the agent's key! (cnf.jwk)
		Alg:        "ed25519",
	}

	sigBytes, sigInputStr, _ := httpsig.Sign(signInput)

	// 7. Fire Request
	req := &pb.CheckRequest{
		Attributes: &pb.AttributeContext{
			ContextExtensions: map[string]string{
				"aauth_resource_id": "res-jwt",
			},
			Request: &pb.AttributeContext_Request{
				Http: &pb.AttributeContext_HttpRequest{
					Method: "GET",
					Host:   "res.example.com",
					Path:   "/api",
					Headers: map[string]string{
						"signature-key":   sigKeyVal,
						"signature-input": sigInputStr,
						"signature":       `sig=:` + base64.StdEncoding.EncodeToString(sigBytes) + `:`,
					},
				},
			},
		},
	}

	resp, _ := h.Check(context.Background(), req)
	if resp.Status.Code != 0 {
		if resp.Status.Code == 16 {
			denied := resp.HttpResponse.(*pb.CheckResponse_DeniedResponse).DeniedResponse
			t.Fatalf("expected OK, got UNAUTHENTICATED. Body: %s", denied.Body)
		}
		t.Fatalf("expected OK, got %v", resp.Status.Code)
	}

	okResp := resp.HttpResponse.(*pb.CheckResponse_OkResponse).OkResponse

	// Verify upstream headers
	foundLevel := false
	foundAgent := false
	foundDelegate := false

	for _, hdr := range okResp.Headers {
		switch hdr.Header.Key {
		case "x-aauth-level":
			if hdr.Header.Value != "identified" {
				t.Errorf("expected level=identified, got %v", hdr.Header.Value)
			}
			foundLevel = true
		case "x-aauth-agent-server":
			if hdr.Header.Value != "https://agents.example.com" {
				t.Errorf("expected agent-server=https://agents.example.com, got %v", hdr.Header.Value)
			}
			foundAgent = true
		case "x-aauth-delegate":
			if hdr.Header.Value != "test-delegate" {
				t.Errorf("expected delegate=test-delegate, got %v", hdr.Header.Value)
			}
			foundDelegate = true
		}
	}

	if !foundLevel || !foundAgent || !foundDelegate {
		t.Errorf("missing expected headers. level=%v agent=%v delegate=%v", foundLevel, foundAgent, foundDelegate)
		var names []string
		for _, h := range okResp.Headers {
			names = append(names, h.Header.Key)
		}
		t.Logf("Got headers: %s", strings.Join(names, ", "))
	}
}
