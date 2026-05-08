package extauthz

import (
	"testing"

	"aauth-service/internal/config"
)

func TestResolveResourceTokenAud(t *testing.T) {
	rc := &config.ResourceConfig{
		PersonServer: config.PersonServer{
			Issuer: "https://ps.example.com",
		},
		AuthServers: []config.AuthServer{
			{Issuer: "https://auth.example.com"},
		},
		AuthorizationEndpointOverride: "https://override.example.com/resource/token",
	}
	if got := ResolveResourceTokenAud(rc); got != "https://ps.example.com" {
		t.Fatalf("got %q want %q", got, "https://ps.example.com")
	}

	rc = &config.ResourceConfig{
		AuthServers:                   []config.AuthServer{{Issuer: "https://auth.example.com"}},
		AuthorizationEndpointOverride: "https://override.example.com/resource/token",
	}
	if got := ResolveResourceTokenAud(rc); got != "" {
		t.Fatalf("got %q want empty", got)
	}
}
