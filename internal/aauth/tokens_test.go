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

	if header["typ"] != "resource+jwt" {
		t.Errorf("expected typ=resource+jwt, got %v", header["typ"])
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

	// For now, we are just using the raw public key bytes encoded as base64
	thumbprint, err := ExtractJWKThumbprint(pub)
	if err != nil {
		t.Fatalf("ExtractJWKThumbprint failed: %v", err)
	}

	expected := base64.RawURLEncoding.EncodeToString(pub)
	if thumbprint != expected {
		t.Errorf("expected thumbprint %s, got %s", expected, thumbprint)
	}
}
