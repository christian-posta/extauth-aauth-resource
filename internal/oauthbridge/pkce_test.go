package oauthbridge_test

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"aauth-service/internal/oauthbridge"
)

func TestPKCEPair(t *testing.T) {
	verifier, challenge := oauthbridge.NewPKCEPair()
	if verifier == "" || challenge == "" {
		t.Fatal("empty PKCE values")
	}

	// Recompute challenge from verifier and compare.
	h := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(h[:])
	if challenge != want {
		t.Fatalf("challenge mismatch: got %q want %q", challenge, want)
	}
}

func TestPKCEUnique(t *testing.T) {
	v1, _ := oauthbridge.NewPKCEPair()
	v2, _ := oauthbridge.NewPKCEPair()
	if v1 == v2 {
		t.Fatal("verifiers should be unique")
	}
}
