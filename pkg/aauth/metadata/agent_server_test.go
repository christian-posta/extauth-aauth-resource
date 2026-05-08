package metadata_test

import (
	"encoding/json"
	"testing"

	"aauth-service/pkg/aauth/metadata"
)

func boolPtr(b bool) *bool { return &b }

func TestBuildAgentServerMetadata(t *testing.T) {
	t.Run("required field only", func(t *testing.T) {
		m := &metadata.AgentServerMetadata{
			Issuer: "https://agent.example",
		}
		b, err := metadata.BuildAgentServerMetadata(m)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var out map[string]interface{}
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if out["issuer"] != "https://agent.example" {
			t.Errorf("issuer: got %v", out["issuer"])
		}
	})

	t.Run("full metadata round-trip", func(t *testing.T) {
		orig := &metadata.AgentServerMetadata{
			Issuer:                   "https://agent.example",
			JwksURI:                  "https://agent.example/.well-known/jwks.json",
			ClientName:               "My Agent",
			LogoURI:                  "https://agent.example/logo.png",
			LogoDarkURI:              "https://agent.example/logo-dark.png",
			CallbackEndpoint:         "https://agent.example/callback",
			LoginEndpoint:            "https://agent.example/login",
			LocalhostCallbackAllowed: boolPtr(true),
			ClarificationSupported:   boolPtr(false),
			TosURI:                   "https://agent.example/tos",
			PolicyURI:                "https://agent.example/policy",
		}

		b, err := metadata.BuildAgentServerMetadata(orig)
		if err != nil {
			t.Fatalf("build error: %v", err)
		}

		var round metadata.AgentServerMetadata
		if err := json.Unmarshal(b, &round); err != nil {
			t.Fatalf("unmarshal error: %v", err)
		}

		if round.Issuer != orig.Issuer {
			t.Errorf("Issuer: got %q want %q", round.Issuer, orig.Issuer)
		}
		if round.ClientName != orig.ClientName {
			t.Errorf("ClientName: got %q want %q", round.ClientName, orig.ClientName)
		}
		if round.LocalhostCallbackAllowed == nil || *round.LocalhostCallbackAllowed != true {
			t.Errorf("LocalhostCallbackAllowed: got %v want true", round.LocalhostCallbackAllowed)
		}
		if round.ClarificationSupported == nil || *round.ClarificationSupported != false {
			t.Errorf("ClarificationSupported: got %v want false", round.ClarificationSupported)
		}
		if round.TosURI != orig.TosURI {
			t.Errorf("TosURI: got %q want %q", round.TosURI, orig.TosURI)
		}
	})

	t.Run("optional fields omitted when empty", func(t *testing.T) {
		m := &metadata.AgentServerMetadata{
			Issuer: "https://agent.example",
		}
		b, _ := metadata.BuildAgentServerMetadata(m)
		var out map[string]interface{}
		json.Unmarshal(b, &out)

		optional := []string{
			"jwks_uri", "client_name", "logo_uri", "logo_dark_uri",
			"callback_endpoint", "login_endpoint",
			"localhost_callback_allowed", "clarification_supported",
			"tos_uri", "policy_uri",
		}
		for _, key := range optional {
			if _, ok := out[key]; ok {
				t.Errorf("expected %q absent when empty, but found it", key)
			}
		}
	})
}
