package metadata_test

import (
	"encoding/json"
	"testing"

	"aauth-service/pkg/aauth/metadata"
)

func TestBuildResourceMetadata(t *testing.T) {
	t.Run("required fields only", func(t *testing.T) {
		m := &metadata.ResourceMetadata{
			Resource: "https://resource.example",
			JwksURI:  "https://resource.example/.well-known/jwks.json",
		}
		b, err := metadata.BuildResourceMetadata(m)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var out map[string]interface{}
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}

		if out["issuer"] != "https://resource.example" {
			t.Errorf("issuer: got %v", out["issuer"])
		}
		if out["jwks_uri"] != "https://resource.example/.well-known/jwks.json" {
			t.Errorf("jwks_uri: got %v", out["jwks_uri"])
		}
	})

	t.Run("full metadata round-trip", func(t *testing.T) {
		orig := &metadata.ResourceMetadata{
			Resource:              "https://resource.example",
			JwksURI:               "https://resource.example/.well-known/jwks.json",
			ClientName:            "Example Data Service",
			LogoURI:               "https://resource.example/logo.png",
			LogoDarkURI:           "https://resource.example/logo-dark.png",
			AuthorizationEndpoint: "https://resource.example/authorize",
			SignatureWindow:       120,
			SupportedScopes:       []string{"data.read", "data.write"},
			ScopeDescriptions: map[string]string{
				"data.read":  "Read access to your data",
				"data.write": "Write access to your data",
			},
			AdditionalSignatureComponents: []string{"content-type", "content-digest"},
			LoginEndpoint:                 "https://resource.example/login",
			RevocationEndpoint:            "https://resource.example/revoke",
		}

		b, err := metadata.BuildResourceMetadata(orig)
		if err != nil {
			t.Fatalf("build error: %v", err)
		}

		var round metadata.ResourceMetadata
		if err := json.Unmarshal(b, &round); err != nil {
			t.Fatalf("unmarshal error: %v", err)
		}

		if round.Resource != orig.Resource {
			t.Errorf("Resource: got %q want %q", round.Resource, orig.Resource)
		}
		if round.JwksURI != orig.JwksURI {
			t.Errorf("JwksURI: got %q want %q", round.JwksURI, orig.JwksURI)
		}
		if round.ClientName != orig.ClientName {
			t.Errorf("ClientName: got %q want %q", round.ClientName, orig.ClientName)
		}
		if round.SignatureWindow != orig.SignatureWindow {
			t.Errorf("SignatureWindow: got %d want %d", round.SignatureWindow, orig.SignatureWindow)
		}
		if len(round.SupportedScopes) != len(orig.SupportedScopes) {
			t.Errorf("SupportedScopes len: got %d want %d", len(round.SupportedScopes), len(orig.SupportedScopes))
		}
		if len(round.AdditionalSignatureComponents) != len(orig.AdditionalSignatureComponents) {
			t.Errorf("AdditionalSignatureComponents len: got %d want %d",
				len(round.AdditionalSignatureComponents), len(orig.AdditionalSignatureComponents))
		}
	})

	t.Run("optional fields omitted when empty", func(t *testing.T) {
		m := &metadata.ResourceMetadata{
			Resource: "https://resource.example",
			JwksURI:  "https://resource.example/.well-known/jwks.json",
		}
		b, _ := metadata.BuildResourceMetadata(m)
		var out map[string]interface{}
		json.Unmarshal(b, &out)

		optional := []string{
			"client_name", "logo_uri", "logo_dark_uri",
			"authorization_endpoint", "login_endpoint",
			"revocation_endpoint", "signature_window",
		}
		for _, key := range optional {
			if _, ok := out[key]; ok {
				t.Errorf("expected %q to be absent from JSON when empty, but it was present", key)
			}
		}
	})
}
