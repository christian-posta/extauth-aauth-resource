package httpsig

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"policy_engine/pkg/httpsig/structfields"
)

func TestEndToEndSignAndVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	headers := map[string][]string{
		"signature-key": {`scheme="hwk", key="test"`},
		"x-test":        {"value1"},
	}

	now := time.Now().Unix()
	params := structfields.Params{
		{Name: "created", Value: now},
		{Name: "alg", Value: "ed25519"},
	}

	signInput := SignInput{
		Method:     "POST",
		Authority:  "example.com",
		Path:       "/foo",
		Headers:    headers,
		Label:      "aauth",
		Components: []string{"@method", "@authority", "@path", "signature-key", "x-test"},
		Params:     params,
		PrivateKey: priv,
		Alg:        "ed25519",
	}

	sigBytes, sigInputStr, err := Sign(signInput)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Create request with signatures added
	verifyHeaders := map[string][]string{
		"signature-key":   headers["signature-key"],
		"x-test":          headers["x-test"],
		"signature-input": {sigInputStr},
		"signature":       {`aauth=:` + base64.StdEncoding.EncodeToString(sigBytes) + `:`},
	}

	verifyInput := VerifyInput{
		Method:             "POST",
		Authority:          "example.com",
		Path:               "/foo",
		Headers:            verifyHeaders,
		Label:              "aauth",
		RequiredComponents: []string{"@method", "@authority", "@path", "signature-key"},
		AllowedAlgs:        []string{"ed25519"},
		MaxClockSkew:       60 * time.Second,
		PublicKey:          pub,
		Alg:                "ed25519",
	}

	res, err := Verify(verifyInput)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if res.Label != "aauth" {
		t.Errorf("expected label aauth, got %v", res.Label)
	}
	if len(res.Covered) != 5 {
		t.Errorf("expected 5 covered components, got %v", res.Covered)
	}

	// Test failure cases
	// 1. Mutate header
	verifyHeaders["x-test"] = []string{"mutated"}
	_, err = Verify(verifyInput)
	if err != ErrInvalidSignature {
		t.Errorf("expected ErrInvalidSignature, got %v", err)
	}
	verifyHeaders["x-test"] = []string{"value1"} // restore

	// 2. Missing signature-key coverage check
	verifyInput.RequiredComponents = append(verifyInput.RequiredComponents, "missing-header")
	_, err = Verify(verifyInput)
	if err == nil || err == ErrInvalidSignature {
		t.Errorf("expected missing coverage error, got %v", err)
	}
}
