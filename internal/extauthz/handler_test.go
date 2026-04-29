package extauthz_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	pb "aauth-service/gen/proto"
	"aauth-service/internal/aauth"
	"aauth-service/internal/config"
	"aauth-service/internal/extauthz"
	"aauth-service/pkg/httpsig"
	"aauth-service/pkg/httpsig/structfields"
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

	// Verify AAuth-Requirement plus signature guidance headers are present
	denied := resp.HttpResponse.(*pb.CheckResponse_DeniedResponse).DeniedResponse
	found := false
	foundSigErr := false
	foundAcceptSig := false
	for _, hdr := range denied.Headers {
		if hdr.Header.Key == "AAuth-Requirement" {
			found = true
		}
		if hdr.Header.Key == "Signature-Error" {
			foundSigErr = true
		}
		if hdr.Header.Key == "Accept-Signature" {
			foundAcceptSig = true
		}
	}
	if !found {
		t.Errorf("expected AAuth-Requirement header")
	}
	if !foundSigErr {
		t.Errorf("expected Signature-Error header")
	}
	if !foundAcceptSig {
		t.Errorf("expected Accept-Signature header")
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

	expectedJKT, err := aauth.ExtractJWKThumbprint(pub)
	if err != nil {
		t.Fatal(err)
	}
	dm := respSigned.GetDynamicMetadata()
	if dm == nil {
		t.Fatal("expected CheckResponse.dynamic_metadata for hwk")
	}
	f := dm.GetFields()
	if f["level"].GetStringValue() != "pseudonymous" {
		t.Errorf("dynamic_metadata.level: got %v", f["level"])
	}
	if f["scheme"].GetStringValue() != "hwk" {
		t.Errorf("dynamic_metadata.scheme: got %v", f["scheme"])
	}
	if f["jkt"].GetStringValue() != expectedJKT {
		t.Errorf("dynamic_metadata.jkt: want %q, got %v", expectedJKT, f["jkt"])
	}
}

func TestHandlerReturnsInvalidInputForMissingSignatureKeyCoverage(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	cfg.Resources = []config.ResourceConfigYAML{
		{
			ID:                "res-coverage",
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

	sigKeyVal := `sig=hwk;kty="OKP";crv="Ed25519";x="` + base64.RawURLEncoding.EncodeToString(pub) + `"`
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
		Components: []string{"@method", "@authority", "@path"},
		Params:     params,
		PrivateKey: priv,
		Alg:        "ed25519",
	}

	sigBytes, sigInputStr, err := httpsig.Sign(signInput)
	if err != nil {
		t.Fatal(err)
	}

	req := &pb.CheckRequest{
		Attributes: &pb.AttributeContext{
			ContextExtensions: map[string]string{
				"aauth_resource_id": "res-coverage",
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
	if resp.Status.Code != 16 {
		t.Fatalf("expected UNAUTHENTICATED, got %v", resp.Status.Code)
	}

	denied := resp.HttpResponse.(*pb.CheckResponse_DeniedResponse).DeniedResponse
	var signatureError string
	for _, hdr := range denied.Headers {
		if hdr.Header.Key == "Signature-Error" {
			signatureError = hdr.Header.Value
			break
		}
	}
	if signatureError == "" {
		t.Fatal("expected Signature-Error header")
	}

	dict, err := structfields.ParseDictionary(signatureError)
	if err != nil {
		t.Fatalf("failed to parse Signature-Error: %v", err)
	}
	errItem, ok := dict.Get("error")
	if !ok {
		t.Fatal("expected error member in Signature-Error")
	}
	if got := errItem.(structfields.Item).Value.(structfields.Token); got != structfields.Token(aauth.ErrInvalidInput.Error()) {
		t.Fatalf("expected invalid_input, got %s", got)
	}
	if _, ok := dict.Get("required_input"); !ok {
		t.Fatal("expected required_input in Signature-Error")
	}
}

func TestHandlerDeniesUnknownHostWithoutResourceMapping(t *testing.T) {
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

	req := &pb.CheckRequest{
		Attributes: &pb.AttributeContext{
			Request: &pb.AttributeContext_Request{
				Http: &pb.AttributeContext_HttpRequest{
					Method: "GET",
					Host:   "unknown.example.com",
					Path:   "/api",
				},
			},
		},
	}

	resp, err := h.Check(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status.Code != 7 {
		t.Fatalf("expected PERMISSION_DENIED, got %v", resp.Status.Code)
	}
}
