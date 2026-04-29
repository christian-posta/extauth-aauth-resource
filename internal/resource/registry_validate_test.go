package resource

import (
	"testing"
	"time"

	"aauth-service/internal/config"
)

func TestNewRegistryRejectsInvalidAllowedSchemes(t *testing.T) {
	cfg := &config.Config{
		Resources: []config.ResourceConfigYAML{
			{
				ID:                            "bad",
				Issuer:                        "https://x.example",
				Hosts:                         []string{"x.example"},
				SignatureWindow:               time.Minute,
				AllowPseudonymous:             true,
				AllowedSignatureKeySchemes:    []string{"jwt", "unknown"},
				AuthorizationEndpoint:         "https://auth.example/authorize",
				SigningKey:                    config.SigningKeyYAML{Kid: "k"},
				AdditionalSignatureComponents: nil,
			},
		},
	}
	_, err := NewRegistry(cfg)
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestNewRegistryRejectsAuthTokenResourceWithoutSigningKey(t *testing.T) {
	cfg := &config.Config{
		Resources: []config.ResourceConfigYAML{
			{
				ID:              "mode3-resource",
				Issuer:          "https://x.example",
				Hosts:           []string{"x.example"},
				SignatureWindow: time.Minute,
				Access:          config.AccessConfigYAML{Require: "auth-token"},
				PersonServer:    config.PersonServerYAML{Issuer: "https://ps.example.com"},
			},
		},
	}
	_, err := NewRegistry(cfg)
	if err == nil {
		t.Fatal("expected validation error")
	}
}
