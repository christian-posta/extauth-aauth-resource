package sigkey

import (
	"testing"
)

func TestParseHWK(t *testing.T) {
	// Spec format: scheme is the Item value (Token), JWK params follow as item params.
	input := `sig=hwk;kty="OKP";crv="Ed25519";x="test-x"`
	parsed, err := Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if parsed.Scheme != SchemeHWK {
		t.Errorf("expected hwk, got %v", parsed.Scheme)
	}

	if parsed.HWK["kty"] != "OKP" {
		t.Errorf("expected kty=OKP, got %v", parsed.HWK["kty"])
	}
	if parsed.HWK["x"] != "test-x" {
		t.Errorf("expected x=test-x, got %v", parsed.HWK["x"])
	}
}

func TestParseJWT(t *testing.T) {
	input := `sig=jwt;jwt="eyJ0eXAi...";keyid="foo"`
	parsed, err := Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if parsed.Scheme != SchemeJWT {
		t.Errorf("expected jwt, got %v", parsed.Scheme)
	}
	if parsed.JWT != "eyJ0eXAi..." {
		t.Errorf("expected jwt string, got %v", parsed.JWT)
	}
	if parsed.KeyID != "foo" {
		t.Errorf("expected keyid=foo, got %v", parsed.KeyID)
	}
}

func TestParseJWKSURI(t *testing.T) {
	input := `sig=jwks_uri;uri="https://example.com/jwks.json"`
	parsed, err := Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if parsed.Scheme != SchemeJWKSURI {
		t.Errorf("expected jwks_uri, got %v", parsed.Scheme)
	}
	if parsed.JWKSURI != "https://example.com/jwks.json" {
		t.Errorf("expected uri, got %v", parsed.JWKSURI)
	}
}

func TestParseUnsupported(t *testing.T) {
	input := `sig=x509`
	_, err := Parse(input)
	if err != ErrUnsupportedScheme {
		t.Errorf("expected ErrUnsupportedScheme, got %v", err)
	}
}
