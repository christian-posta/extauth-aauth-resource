package aauth

import (
	"encoding/base64"
	"testing"
	"time"

	"aauth-service/internal/config"
)

func TestVerifyRejectsInvalidHWKPublicKey(t *testing.T) {
	// 3 bytes is not a valid Ed25519 public key.
	x64 := base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3})
	headers := map[string][]string{
		"signature-key":   {`sig=hwk;kty="OKP";crv="Ed25519";x="` + x64 + `"`},
		"signature-input": {`sig=("@method" "@authority" "@path" "signature-key");created=1;alg="ed25519"`},
		"signature":       {`sig=:AQID:`},
	}

	rc := &config.ResourceConfig{
		Issuer:            "https://resource.example.com",
		AllowPseudonymous: true,
		SignatureWindow:   60 * time.Second,
	}

	result := Verify(rc, "GET", "resource.example.com", "/api", headers, nil)
	if result.Err != ErrInvalidKey {
		t.Fatalf("expected ErrInvalidKey, got %v", result.Err)
	}
}
