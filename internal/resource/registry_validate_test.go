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
