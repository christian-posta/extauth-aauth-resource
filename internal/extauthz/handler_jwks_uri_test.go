package extauthz_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"

	pb "aauth-service/gen/proto"
	"aauth-service/internal/config"
	"aauth-service/internal/extauthz"
	"aauth-service/internal/jwksfetch"
	"aauth-service/internal/policy"
	"aauth-service/internal/resource"
	"aauth-service/pkg/httpsig"
	"aauth-service/pkg/httpsig/structfields"
)

func TestHandlerJwksURI(t *testing.T) {
	// 1. Generate keys
	agentServerPub, agentServerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// 2. Setup mock discovery metadata + JWKS
	agentID := "https://agents.example.com"
	dwk := "aauth-agent.json"
	discoveryURL := agentID + "/.well-known/" + dwk
	jwksURI := "https://agents.example.com/jwks.json"

	agentServerKey, err := jwk.FromRaw(agentServerPub)
	if err != nil {
		t.Fatal(err)
	}
	agentServerKey.Set(jwk.KeyIDKey, "as-key-1")

	mockJwks := jwksfetch.NewMockClient()
	set := jwk.NewSet()
	set.AddKey(agentServerKey)
	mockJwks.Metadata[discoveryURL] = map[string]interface{}{
		"jwks_uri": jwksURI,
	}
	mockJwks.Keysets[jwksURI] = set

	// 3. Setup Config and Handler
	cfg := &config.Config{}
	cfg.Resources = []config.ResourceConfigYAML{
		{
			ID:     "res-jwks-uri",
			Issuer: "https://res.example.com",
			Hosts:  []string{"res.example.com"},
			AgentServers: []config.AgentServerYAML{
				{Issuer: agentID, JwksURI: jwksURI},
			},
			SignatureWindow: 60 * time.Second,
		},
	}

	reg, _ := resource.NewRegistry(cfg)
	engine := policy.NewDefaultEngine()
	aauthHandler := extauthz.NewAAuthHandler(engine, mockJwks)

	h := extauthz.NewTestHandler(reg, aauthHandler)

	// 4. Build Signature-Key header (jwks_uri scheme)
	sigKeyVal := `sig=jwks_uri;id="` + agentID + `";dwk="` + dwk + `";kid="as-key-1"`

	// 5. Build HTTP Signature
	headers := map[string][]string{
		"signature-key": {sigKeyVal},
	}

	now := time.Now().Unix()
	params := structfields.Params{
		{Name: "created", Value: now},
		{Name: "alg", Value: "ed25519"},
		{Name: "keyid", Value: "as-key-1"},
	}

	signInput := httpsig.SignInput{
		Method:     "GET",
		Authority:  "res.example.com",
		Path:       "/api",
		Headers:    headers,
		Label:      "sig",
		Components: []string{"@method", "@authority", "@path", "signature-key"},
		Params:     params,
		PrivateKey: agentServerPriv, // Signed directly by the agent server's key
		Alg:        "ed25519",
	}

	sigBytes, sigInputStr, _ := httpsig.Sign(signInput)

	// 6. Fire Request
	req := &pb.CheckRequest{
		Attributes: &pb.AttributeContext{
			ContextExtensions: map[string]string{
				"aauth_resource_id": "res-jwks-uri",
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
		}
	}

	if !foundLevel || !foundAgent {
		t.Errorf("missing expected headers. level=%v agent=%v", foundLevel, foundAgent)
	}

	dm := resp.GetDynamicMetadata()
	if dm == nil {
		t.Fatal("expected CheckResponse.dynamic_metadata for jwks_uri")
	}
	f := dm.GetFields()
	if f["level"].GetStringValue() != "identified" {
		t.Errorf("dynamic_metadata.level: got %v", f["level"])
	}
	if f["scheme"].GetStringValue() != "jwks_uri" {
		t.Errorf("dynamic_metadata.scheme: got %v", f["scheme"])
	}
	if f["issuer"].GetStringValue() != agentID {
		t.Errorf("dynamic_metadata.issuer: got %v", f["issuer"])
	}
	if f["agent_server"].GetStringValue() != agentID {
		t.Errorf("dynamic_metadata.agent_server: got %v", f["agent_server"])
	}
	if f["key_id"].GetStringValue() != "as-key-1" {
		t.Errorf("dynamic_metadata.key_id: got %v", f["key_id"])
	}
	if f["jkt"].GetStringValue() == "" {
		t.Errorf("dynamic_metadata.jkt missing")
	}
}
