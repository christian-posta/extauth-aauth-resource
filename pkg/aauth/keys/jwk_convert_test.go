package keys_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"aauth-service/pkg/aauth/keys"
)

func TestEd25519PublicKeyRoundTrip(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	k, err := keys.Ed25519PublicKeyToJWK(pub, "test-kid")
	if err != nil {
		t.Fatalf("Ed25519PublicKeyToJWK: %v", err)
	}

	if k.KeyID() != "test-kid" {
		t.Errorf("kid: got %q, want %q", k.KeyID(), "test-kid")
	}

	got, err := keys.JWKToEd25519PublicKey(k)
	if err != nil {
		t.Fatalf("JWKToEd25519PublicKey: %v", err)
	}

	if !pub.Equal(got) {
		t.Error("round-trip: public key mismatch")
	}
}

func TestEd25519PublicKeyToJWK_NoKid(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	k, err := keys.Ed25519PublicKeyToJWK(pub, "")
	if err != nil {
		t.Fatalf("Ed25519PublicKeyToJWK: %v", err)
	}

	if k.KeyID() != "" {
		t.Errorf("expected empty kid, got %q", k.KeyID())
	}
}

func TestThumbprint(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	k, err := keys.Ed25519PublicKeyToJWK(pub, "")
	if err != nil {
		t.Fatalf("Ed25519PublicKeyToJWK: %v", err)
	}

	tp, err := keys.Thumbprint(k)
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}

	if len(tp) == 0 {
		t.Error("expected non-empty thumbprint")
	}

	// Compute again — must be deterministic
	tp2, err := keys.Thumbprint(k)
	if err != nil {
		t.Fatalf("Thumbprint (2nd): %v", err)
	}

	if tp != tp2 {
		t.Errorf("thumbprint not deterministic: %q vs %q", tp, tp2)
	}
}

func TestThumbprint_DifferentKeysProduceDifferentThumbprints(t *testing.T) {
	pub1, _, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)

	k1, _ := keys.Ed25519PublicKeyToJWK(pub1, "")
	k2, _ := keys.Ed25519PublicKeyToJWK(pub2, "")

	tp1, _ := keys.Thumbprint(k1)
	tp2, _ := keys.Thumbprint(k2)

	if tp1 == tp2 {
		t.Error("different keys produced the same thumbprint")
	}
}
