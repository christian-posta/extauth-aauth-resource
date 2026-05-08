package metadata_test

import (
	"encoding/json"
	"testing"

	"aauth-service/pkg/aauth/metadata"
)

func TestBuildPersonServerMetadata(t *testing.T) {
	t.Run("required fields only", func(t *testing.T) {
		m := &metadata.PersonServerMetadata{
			Issuer:        "https://ps.example",
			TokenEndpoint: "https://ps.example/token",
			JwksURI:       "https://ps.example/.well-known/jwks.json",
		}
		b, err := metadata.BuildPersonServerMetadata(m)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var out map[string]interface{}
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if out["issuer"] != "https://ps.example" {
			t.Errorf("issuer: got %v", out["issuer"])
		}
		if out["token_endpoint"] != "https://ps.example/token" {
			t.Errorf("token_endpoint: got %v", out["token_endpoint"])
		}
		if out["jwks_uri"] != "https://ps.example/.well-known/jwks.json" {
			t.Errorf("jwks_uri: got %v", out["jwks_uri"])
		}
	})

	t.Run("full metadata round-trip", func(t *testing.T) {
		orig := &metadata.PersonServerMetadata{
			Issuer:                 "https://ps.example",
			TokenEndpoint:          "https://ps.example/token",
			JwksURI:                "https://ps.example/.well-known/jwks.json",
			MissionEndpoint:        "https://ps.example/mission",
			PermissionEndpoint:     "https://ps.example/permission",
			AuditEndpoint:          "https://ps.example/audit",
			InteractionEndpoint:    "https://ps.example/interact",
			MissionControlEndpoint: "https://ps.example/mission-control",
			LoginEndpoint:          "https://ps.example/login",
			RevocationEndpoint:     "https://ps.example/revoke",
			ScopesSupported:        []string{"openid", "profile"},
			ClaimsSupported:        []string{"sub", "name", "email"},
		}

		b, err := metadata.BuildPersonServerMetadata(orig)
		if err != nil {
			t.Fatalf("build error: %v", err)
		}

		var round metadata.PersonServerMetadata
		if err := json.Unmarshal(b, &round); err != nil {
			t.Fatalf("unmarshal error: %v", err)
		}

		if round.Issuer != orig.Issuer {
			t.Errorf("Issuer: got %q want %q", round.Issuer, orig.Issuer)
		}
		if round.TokenEndpoint != orig.TokenEndpoint {
			t.Errorf("TokenEndpoint: got %q want %q", round.TokenEndpoint, orig.TokenEndpoint)
		}
		if round.MissionControlEndpoint != orig.MissionControlEndpoint {
			t.Errorf("MissionControlEndpoint: got %q want %q", round.MissionControlEndpoint, orig.MissionControlEndpoint)
		}
		if len(round.ScopesSupported) != len(orig.ScopesSupported) {
			t.Errorf("ScopesSupported len: got %d want %d", len(round.ScopesSupported), len(orig.ScopesSupported))
		}
		if len(round.ClaimsSupported) != len(orig.ClaimsSupported) {
			t.Errorf("ClaimsSupported len: got %d want %d", len(round.ClaimsSupported), len(orig.ClaimsSupported))
		}
	})

	t.Run("optional fields omitted when empty", func(t *testing.T) {
		m := &metadata.PersonServerMetadata{
			Issuer:        "https://ps.example",
			TokenEndpoint: "https://ps.example/token",
			JwksURI:       "https://ps.example/.well-known/jwks.json",
		}
		b, _ := metadata.BuildPersonServerMetadata(m)
		var out map[string]interface{}
		json.Unmarshal(b, &out)

		optional := []string{
			"mission_endpoint", "permission_endpoint", "audit_endpoint",
			"interaction_endpoint", "mission_control_endpoint",
			"login_endpoint", "revocation_endpoint",
			"scopes_supported", "claims_supported",
		}
		for _, key := range optional {
			if _, ok := out[key]; ok {
				t.Errorf("expected %q absent when empty, but found it", key)
			}
		}
	})
}
