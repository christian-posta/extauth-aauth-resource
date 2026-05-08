package metadata_test

import (
	"encoding/json"
	"testing"

	"aauth-service/pkg/aauth/metadata"
)

func TestBuildAuthServerMetadata(t *testing.T) {
	t.Run("required fields only", func(t *testing.T) {
		m := &metadata.AuthServerMetadata{
			Issuer:        "https://as.example",
			TokenEndpoint: "https://as.example/token",
			JwksURI:       "https://as.example/.well-known/jwks.json",
		}
		b, err := metadata.BuildAuthServerMetadata(m)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var out map[string]interface{}
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if out["issuer"] != "https://as.example" {
			t.Errorf("issuer: got %v", out["issuer"])
		}
		if out["token_endpoint"] != "https://as.example/token" {
			t.Errorf("token_endpoint: got %v", out["token_endpoint"])
		}
		if out["jwks_uri"] != "https://as.example/.well-known/jwks.json" {
			t.Errorf("jwks_uri: got %v", out["jwks_uri"])
		}
	})

	t.Run("full metadata round-trip", func(t *testing.T) {
		orig := &metadata.AuthServerMetadata{
			Issuer:              "https://as.example",
			TokenEndpoint:       "https://as.example/token",
			JwksURI:             "https://as.example/.well-known/jwks.json",
			InteractionEndpoint: "https://as.example/interact",
			LoginEndpoint:       "https://as.example/login",
			RevocationEndpoint:  "https://as.example/revoke",
		}

		b, err := metadata.BuildAuthServerMetadata(orig)
		if err != nil {
			t.Fatalf("build error: %v", err)
		}

		var round metadata.AuthServerMetadata
		if err := json.Unmarshal(b, &round); err != nil {
			t.Fatalf("unmarshal error: %v", err)
		}

		if round.Issuer != orig.Issuer {
			t.Errorf("Issuer: got %q want %q", round.Issuer, orig.Issuer)
		}
		if round.InteractionEndpoint != orig.InteractionEndpoint {
			t.Errorf("InteractionEndpoint: got %q want %q", round.InteractionEndpoint, orig.InteractionEndpoint)
		}
		if round.RevocationEndpoint != orig.RevocationEndpoint {
			t.Errorf("RevocationEndpoint: got %q want %q", round.RevocationEndpoint, orig.RevocationEndpoint)
		}
	})

	t.Run("optional fields omitted when empty", func(t *testing.T) {
		m := &metadata.AuthServerMetadata{
			Issuer:        "https://as.example",
			TokenEndpoint: "https://as.example/token",
			JwksURI:       "https://as.example/.well-known/jwks.json",
		}
		b, _ := metadata.BuildAuthServerMetadata(m)
		var out map[string]interface{}
		json.Unmarshal(b, &out)

		optional := []string{"interaction_endpoint", "login_endpoint", "revocation_endpoint"}
		for _, key := range optional {
			if _, ok := out[key]; ok {
				t.Errorf("expected %q absent when empty, but found it", key)
			}
		}
	})
}
