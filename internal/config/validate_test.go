package config

import (
	"testing"
	"time"
)

func baseResource() *ResourceConfig {
	return &ResourceConfig{
		ID:                "r1",
		Issuer:            "https://r.example",
		AllowPseudonymous: true,
		SignatureWindow:   time.Minute,
	}
}

func TestValidateResourceAllowedSchemesUnknown(t *testing.T) {
	rc := baseResource()
	rc.AllowedSignatureKeySchemes = []string{"hwk", "nope"}
	err := ValidateResource(rc)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateResourceHWKRequiresPseudonymous(t *testing.T) {
	rc := baseResource()
	rc.AllowPseudonymous = false
	rc.AllowedSignatureKeySchemes = []string{"hwk", "jwt"}
	err := ValidateResource(rc)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateResourceJWTTypesWithoutJWTScheme(t *testing.T) {
	rc := baseResource()
	rc.AllowedSignatureKeySchemes = []string{"jwks_uri"}
	rc.AllowedJWTTypes = []string{JWTTypeAgent}
	err := ValidateResource(rc)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateResourceJWTTypesUnknown(t *testing.T) {
	rc := baseResource()
	rc.AllowedSignatureKeySchemes = []string{"jwt"}
	rc.AllowedJWTTypes = []string{"aa-agent+jwt", "other"}
	err := ValidateResource(rc)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateResourceOK(t *testing.T) {
	rc := baseResource()
	rc.AllowedSignatureKeySchemes = []string{SchemeJWKSURI, SchemeJWT}
	rc.AllowedJWTTypes = []string{JWTTypeAgent}
	if err := ValidateResource(rc); err != nil {
		t.Fatal(err)
	}
}

func TestNormalizeAndDedupeTokens(t *testing.T) {
	got := NormalizeAndDedupeTokens([]string{" JWT ", "hwk", "HWK"})
	if len(got) != 2 {
		t.Fatalf("got %v", got)
	}
	if got[0] != "jwt" || got[1] != "hwk" {
		t.Fatalf("got %v", got)
	}
}
