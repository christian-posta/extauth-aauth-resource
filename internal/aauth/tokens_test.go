package aauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"policy_engine/internal/config"
)

func TestMintResourceToken(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	rc := &config.ResourceConfig{
		SigningKey: config.SigningKey{
			Kid: "test-kid-1",
		},
	}

	claims := ResourceTokenClaims{
		Iss:      "https://resource.example.com",
		Aud:      "https://auth.example.com",
		AgentJKT: "test-jkt",
		Exp:      time.Now().Add(5 * time.Minute).Unix(),
		Jti:      "test-jti-1",
	}

	token, err := MintResourceToken(rc, claims, priv)
	if err != nil {
		t.Fatalf("MintResourceToken failed: %v", err)
	}

	// Verify token format
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 token parts, got %d", len(parts))
	}

	// Verify header
	header, claimsParsed, err := parseJWTUnverified(token)
	if err != nil {
		t.Fatalf("parseJWTUnverified failed: %v", err)
	}

	if header["typ"] != "aa-resource+jwt" {
		t.Errorf("expected typ=aa-resource+jwt, got %v", header["typ"])
	}
	if header["kid"] != "test-kid-1" {
		t.Errorf("expected kid=test-kid-1, got %v", header["kid"])
	}
	if header["alg"] != "EdDSA" {
		t.Errorf("expected alg=EdDSA, got %v", header["alg"])
	}

	// Verify claims
	if claimsParsed["iss"] != "https://resource.example.com" {
		t.Errorf("expected iss=https://resource.example.com, got %v", claimsParsed["iss"])
	}
	if claimsParsed["agent_jkt"] != "test-jkt" {
		t.Errorf("expected agent_jkt=test-jkt, got %v", claimsParsed["agent_jkt"])
	}

	// Verify signature
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("failed to decode signature: %v", err)
	}

	signedContent := parts[0] + "." + parts[1]
	if !ed25519.Verify(pub, []byte(signedContent), sig) {
		t.Errorf("token signature verification failed")
	}
}

func TestExtractJWKThumbprint(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	thumbprint, err := ExtractJWKThumbprint(pub)
	if err != nil {
		t.Fatalf("ExtractJWKThumbprint failed: %v", err)
	}

	// RFC 7638: SHA-256 of canonical JWK JSON, base64url without padding = 43 chars.
	if len(thumbprint) != 43 {
		t.Errorf("expected 43-char base64url thumbprint, got len=%d: %s", len(thumbprint), thumbprint)
	}

	// Must be stable — same key produces same thumbprint.
	thumbprint2, _ := ExtractJWKThumbprint(pub)
	if thumbprint != thumbprint2 {
		t.Errorf("thumbprint not stable: %s != %s", thumbprint, thumbprint2)
	}

	// Must differ for different keys.
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	thumbprint3, _ := ExtractJWKThumbprint(pub2)
	if thumbprint == thumbprint3 {
		t.Errorf("different keys produced same thumbprint")
	}
}
