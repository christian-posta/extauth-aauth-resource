package extauthz_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	pb "policy_engine/gen/proto"
	"policy_engine/internal/config"
	"policy_engine/internal/extauthz"
	"policy_engine/pkg/httpsig"
	"policy_engine/pkg/httpsig/structfields"
)

func TestHandler(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	cfg.Resources = []config.ResourceConfigYAML{
		{
			ID:                "res-1",
			Issuer:            "https://res.example.com",
			Hosts:             []string{"res.example.com"},
			AllowPseudonymous: true,
			SignatureWindow:   60 * time.Second,
		},
	}

	h, err := extauthz.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Unsigned request -> 401
	reqUnsigned := &pb.CheckRequest{
		Attributes: &pb.AttributeContext{
			ContextExtensions: map[string]string{
				"aauth_resource_id": "res-1",
			},
			Request: &pb.AttributeContext_Request{
				Http: &pb.AttributeContext_HttpRequest{
					Method: "GET",
					Host:   "res.example.com",
					Path:   "/api",
				},
			},
		},
	}

	resp, _ := h.Check(context.Background(), reqUnsigned)
	if resp.Status.Code != 16 { // UNAUTHENTICATED
		t.Errorf("expected 401, got %v", resp.Status.Code)
	}

	// Verify AAuth-Requirement header is present
	denied := resp.HttpResponse.(*pb.CheckResponse_DeniedResponse).DeniedResponse
	found := false
	for _, hdr := range denied.Headers {
		if hdr.Header.Key == "AAuth-Requirement" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected AAuth-Requirement header")
	}

	// 2. Signed request (HWK)
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

	t.Logf("sigInputStr: %s", sigInputStr)

	reqSigned := &pb.CheckRequest{
		Attributes: &pb.AttributeContext{
			ContextExtensions: map[string]string{
				"aauth_resource_id": "res-1",
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
	if respSigned.Status.Code != 0 {
		t.Fatalf("expected OK, got %v", respSigned.Status.Code)
	}

	okResp := respSigned.HttpResponse.(*pb.CheckResponse_OkResponse).OkResponse
	foundLevel := false
	for _, hdr := range okResp.Headers {
		if hdr.Header.Key == "x-aauth-level" {
			if hdr.Header.Value != "pseudonymous" {
				t.Errorf("expected pseudonymous level, got %v", hdr.Header.Value)
			}
			foundLevel = true
			break
		}
	}
	if !foundLevel {
		t.Errorf("expected x-aauth-level header")
	}
}
