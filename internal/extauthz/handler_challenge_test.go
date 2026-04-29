package extauthz_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	pb "aauth-service/gen/proto"
	"aauth-service/internal/config"
	"aauth-service/internal/extauthz"
	"aauth-service/pkg/httpsig"
	"aauth-service/pkg/httpsig/structfields"
)

func TestHandlerChallengeWithToken(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Create resource key to issue the resource token
	_, resPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	cfg.Resources = []config.ResourceConfigYAML{
		{
			ID:                "res-2",
			Issuer:            "https://res.example.com",
			Hosts:             []string{"res.example.com"},
			SigningKey:        config.SigningKeyYAML{Kid: "res-key-1"},
			AllowPseudonymous: false, // Force challenge!
			SignatureWindow:   60 * time.Second,
		},
	}

	h, err := extauthz.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Nasty hack to inject the private key for tests since we're not loading from file
	h.InjectTestKey("res-2", resPriv)

	pubBytes := pub
	x64 := base64.RawURLEncoding.EncodeToString(pubBytes)
	sigKeyVal := `sig=hwk;kty="OKP";crv="Ed25519";x="` + x64 + `"`

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
		PrivateKey: priv,
		Alg:        "ed25519",
	}

	sigBytes, sigInputStr, _ := httpsig.Sign(signInput)

	reqSigned := &pb.CheckRequest{
		Attributes: &pb.AttributeContext{
			ContextExtensions: map[string]string{
				"aauth_resource_id": "res-2",
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

	respSigned, _ := h.Check(context.Background(), reqSigned)
	if respSigned.Status.Code != 16 {
		t.Fatalf("expected UNAUTHENTICATED, got %v", respSigned.Status.Code)
	}

	denied := respSigned.HttpResponse.(*pb.CheckResponse_DeniedResponse).DeniedResponse
	foundHeader := ""
	for _, hdr := range denied.Headers {
		if hdr.Header.Key == "AAuth-Requirement" {
			foundHeader = hdr.Header.Value
			break
		}
	}

	if foundHeader == "" {
		t.Fatalf("missing AAuth-Requirement header")
	}

	t.Logf("AAuth-Requirement: %s", foundHeader)

	dict, err := structfields.ParseDictionary(foundHeader)
	if err != nil {
		t.Fatalf("failed to parse AAuth-Requirement: %v", err)
	}

	tokenItem, ok := dict.Get("resource-token")
	if !ok {
		t.Fatalf("missing resource-token in AAuth-Requirement")
	}

	tokenStr, ok := tokenItem.(structfields.Item).Value.(string)
	if !ok {
		t.Fatalf("resource-token is not a String: %T", tokenItem.(structfields.Item).Value)
	}

	if tokenStr == "" || tokenStr == "dummy.token.sig" {
		t.Fatalf("invalid or dummy token returned: %v", tokenStr)
	}
}
