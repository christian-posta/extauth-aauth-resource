package aauth

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestVerifyReturnsDiagnosticsForMissingHeaders(t *testing.T) {
	opts := testVerifyOptions()

	res := Verify(context.Background(), opts, "GET", "resource.example.com", "/api", http.Header{}, nil)
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

func testVerifyOptions() VerifyOptions {
	return VerifyOptions{
		Issuer:          "https://resource.example.com",
		SignatureWindow: 60 * time.Second,
	}
}
