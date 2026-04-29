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

	pb "aauth-service/gen/proto"
	"aauth-service/internal/config"
	"aauth-service/internal/extauthz"
	"aauth-service/internal/jwksfetch"
	"aauth-service/internal/policy"
	"aauth-service/internal/resource"
	"aauth-service/pkg/httpsig"
	"aauth-service/pkg/httpsig/structfields"
)

func TestHandlerAuthJWT(t *testing.T) {
	agentPub, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	authServerPub, authServerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	jwksURI := "https://auth.example.com/jwks.json"

	authServerKey, _ := jwk.FromRaw(authServerPub)
	authServerKey.Set(jwk.KeyIDKey, "as-key-2")

	mockJwks := jwksfetch.NewMockClient()
	set := jwk.NewSet()
	set.AddKey(authServerKey)
	// AAuth: well-known metadata at {iss}/.well-known/{dwk} has jwks_uri; load keys from that URL.
	discoveryURL := "https://auth.example.com/.well-known/aauth-access.json"
	mockJwks.Metadata[discoveryURL] = map[string]interface{}{"jwks_uri": jwksURI}
	mockJwks.Keysets[jwksURI] = set

	cfg := &config.Config{}
	cfg.Resources = []config.ResourceConfigYAML{
		{
			ID:     "res-auth-jwt",
			Issuer: "https://res.example.com",
			Hosts:  []string{"res.example.com"},
			AuthServers: []config.AuthServerYAML{
				{Issuer: "https://auth.example.com", JwksURI: jwksURI},
			},
			SignatureWindow: 60 * time.Second,
		},
	}

	reg, _ := resource.NewRegistry(cfg)
	engine := policy.NewDefaultEngine()
	aauthHandler := extauthz.NewAAuthHandler(engine, mockJwks)

	h := extauthz.NewTestHandler(reg, aauthHandler)

	agentKeyJWK, _ := jwk.FromRaw(agentPub)
	jwkBytes, _ := json.Marshal(agentKeyJWK)
	var jwkMap map[string]interface{}
	json.Unmarshal(jwkBytes, &jwkMap)

	// SPEC §9.4.3: act.sub is the agent identifier (same as the agent claim), not cnf.jwk thumbprint.
	const agentID = "aauth:test-agent@agents.example.com"

	claims := map[string]interface{}{
		"iss":   "https://auth.example.com",
		"dwk":   "aauth-access.json",
		"sub":   "test-delegate",
		"aud":   "https://res.example.com",
		"agent": agentID,
		"scope": "read:data write:data",
		"txn":   "txn-123",
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
		"act":   map[string]interface{}{"sub": agentID},
		"cnf": map[string]interface{}{
			"jwk": jwkMap,
		},
	}

	header := map[string]interface{}{
		"typ": "aa-auth+jwt",
		"alg": "EdDSA",
		"kid": "as-key-2",
	}

	headerBytes, _ := json.Marshal(header)
	claimsBytes, _ := json.Marshal(claims)

	unsignedToken := base64.RawURLEncoding.EncodeToString(headerBytes) + "." + base64.RawURLEncoding.EncodeToString(claimsBytes)
	sig := ed25519.Sign(authServerPriv, []byte(unsignedToken))
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

	req := &pb.CheckRequest{
		Attributes: &pb.AttributeContext{
			ContextExtensions: map[string]string{
				"aauth_resource_id": "res-auth-jwt",
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

	foundLevel := false
	foundAgent := false
	foundDelegate := false
	foundScope := false

	for _, hdr := range okResp.Headers {
		switch hdr.Header.Key {
		case "x-aauth-level":
			if hdr.Header.Value != "authorized" {
				t.Errorf("expected level=authorized, got %v", hdr.Header.Value)
			}
			foundLevel = true
		case "x-aauth-agent-server":
			if hdr.Header.Value != agentID {
				t.Errorf("expected agent-server=%s, got %v", agentID, hdr.Header.Value)
			}
			foundAgent = true
		case "x-aauth-delegate":
			if hdr.Header.Value != "test-delegate" {
				t.Errorf("expected delegate=test-delegate, got %v", hdr.Header.Value)
			}
			foundDelegate = true
		case "x-aauth-scope":
			if hdr.Header.Value != "read:data write:data" {
				t.Errorf("expected scope, got %v", hdr.Header.Value)
			}
			foundScope = true
		}
	}

	if !foundLevel || !foundAgent || !foundDelegate || !foundScope {
		t.Errorf("missing expected headers. level=%v agent=%v delegate=%v scope=%v", foundLevel, foundAgent, foundDelegate, foundScope)
		var names []string
		for _, h := range okResp.Headers {
			names = append(names, h.Header.Key)
		}
		t.Logf("Got headers: %s", strings.Join(names, ", "))
	}

	dm := resp.GetDynamicMetadata()
	if dm == nil {
		t.Fatal("expected CheckResponse.dynamic_metadata for aa-auth+jwt")
	}
	f := dm.GetFields()
	if f["level"].GetStringValue() != "authorized" {
		t.Errorf("dynamic_metadata.level: got %v", f["level"])
	}
	if f["scheme"].GetStringValue() != "jwt" {
		t.Errorf("dynamic_metadata.scheme: got %v", f["scheme"])
	}
	if f["token_type"].GetStringValue() != "aa-auth+jwt" {
		t.Errorf("dynamic_metadata.token_type: got %v", f["token_type"])
	}
	if f["issuer"].GetStringValue() != "https://auth.example.com" {
		t.Errorf("dynamic_metadata.issuer: got %v", f["issuer"])
	}
	if f["key_id"].GetStringValue() != "as-key-2" {
		t.Errorf("dynamic_metadata.key_id: got %v", f["key_id"])
	}
	if f["jkt"].GetStringValue() == "" {
		t.Errorf("dynamic_metadata.jkt missing")
	}
	if f["agent"].GetStringValue() != agentID {
		t.Errorf("dynamic_metadata.agent: want %q, got %v", agentID, f["agent"])
	}
	if f["sub"].GetStringValue() != "test-delegate" {
		t.Errorf("dynamic_metadata.sub: want test-delegate, got %v", f["sub"])
	}
	if f["scope"].GetStringValue() != "read:data write:data" {
		t.Errorf("dynamic_metadata.scope: got %v", f["scope"])
	}
	if f["txn"].GetStringValue() != "txn-123" {
		t.Errorf("dynamic_metadata.txn: got %v", f["txn"])
	}
	act := f["act"].GetStructValue()
	if act == nil {
		t.Fatal("dynamic_metadata.act missing")
	}
	if act.GetFields()["sub"].GetStringValue() != agentID {
		t.Errorf("dynamic_metadata.act.sub: want %q, got %v", agentID, act.GetFields()["sub"])
	}
}
