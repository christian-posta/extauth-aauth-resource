package aauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	pb "aauth-service/gen/proto"
	"aauth-service/internal/config"
	"aauth-service/pkg/httpsig/structfields"
)

func TestChallengeResponseAuthTokenRequirement(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	rc := &config.ResourceConfig{
		Issuer: "https://resource.example.com",
		SigningKey: config.SigningKey{
			Kid: "resource-kid",
		},
		PrivateKey: priv,
		PersonServer: config.PersonServer{
			Issuer: "https://ps.example.com",
		},
	}

	challenge := NewChallenge(rc, ErrInsufficientScope, &AgentHint{
		AgentIdentifier: "aauth:alice@agents.example.com",
		AgentJKT:        "agent-thumbprint",
		Scope:           "data.read",
	}, true)

	resp := challenge.Response()
	httpResp, ok := resp.HttpResponse.(*pb.CheckResponse_DeniedResponse)
	if !ok {
		t.Fatal("expected denied response")
	}
	denied := httpResp.DeniedResponse

	var headerVal string
	for _, h := range denied.Headers {
		if h.Header.Key == "AAuth-Requirement" {
			headerVal = h.Header.Value
			break
		}
	}
	if headerVal == "" {
		t.Fatal("missing AAuth-Requirement header")
	}

	dict, err := structfields.ParseDictionary(headerVal)
	if err != nil {
		t.Fatalf("parse header: %v", err)
	}

	reqVal, ok := dict.Get("requirement")
	if !ok {
		t.Fatal("missing requirement")
	}
	reqItem := reqVal.(structfields.Item)
	if tok, ok := reqItem.Value.(structfields.Token); !ok || string(tok) != "auth-token" {
		t.Fatalf("unexpected requirement value: %#v", reqItem.Value)
	}

	if _, ok := dict.Get("auth-server"); ok {
		t.Fatal("auth-server should be absent")
	}

	tokenVal, ok := dict.Get("resource-token")
	if !ok {
		t.Fatal("missing resource-token")
	}
	tokenItem := tokenVal.(structfields.Item)
	tokenStr, ok := tokenItem.Value.(string)
	if !ok || tokenStr == "" {
		t.Fatalf("resource-token should be non-empty string, got %#v", tokenItem.Value)
	}

	jose, claims, err := parseJWTUnverified(tokenStr)
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	if jose["typ"] != "aa-resource+jwt" {
		t.Fatalf("typ=%v", jose["typ"])
	}
	if claims["dwk"] != "aauth-resource.json" {
		t.Fatalf("dwk=%v", claims["dwk"])
	}
	if claims["aud"] != "https://ps.example.com" {
		t.Fatalf("aud=%v", claims["aud"])
	}
	if claims["agent"] != "aauth:alice@agents.example.com" {
		t.Fatalf("agent=%v", claims["agent"])
	}
	if claims["agent_jkt"] != "agent-thumbprint" {
		t.Fatalf("agent_jkt=%v", claims["agent_jkt"])
	}

	iat, ok := claims["iat"].(float64)
	if !ok {
		t.Fatalf("iat type=%T", claims["iat"])
	}
	exp, ok := claims["exp"].(float64)
	if !ok {
		t.Fatalf("exp type=%T", claims["exp"])
	}
	if time.Unix(int64(exp), 0).Sub(time.Unix(int64(iat), 0)) > 5*time.Minute {
		t.Fatalf("exp-iat exceeded 5m: %v", time.Unix(int64(exp), 0).Sub(time.Unix(int64(iat), 0)))
	}
}
