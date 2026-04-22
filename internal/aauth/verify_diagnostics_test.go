package aauth

import (
	"testing"
	"time"

	"policy_engine/internal/config"
)

func TestVerifyReturnsDiagnosticsForMissingHeaders(t *testing.T) {
	rc := testResourceConfig()

	res := Verify(rc, "GET", "resource.example.com", "/api", map[string][]string{}, nil)
	if res.Err != ErrMissingSignature {
		t.Fatalf("expected ErrMissingSignature, got %v", res.Err)
	}
	if res.Diagnostics == nil {
		t.Fatal("expected diagnostics")
	}
	if res.Diagnostics.Stage != "headers" {
		t.Fatalf("expected diagnostics stage=headers, got %s", res.Diagnostics.Stage)
	}
	if res.Diagnostics.Detail == "" {
		t.Fatal("expected diagnostics detail")
	}
}

func testResourceConfig() *config.ResourceConfig {
	return &config.ResourceConfig{
		Issuer:          "https://resource.example.com",
		SignatureWindow: 60 * time.Second,
	}
}
