package transport_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"

	"aauth-service/pkg/aauth/agent"
	"aauth-service/pkg/aauth/transport"
)

func ExampleNewSigningTransport() {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return
	}
	signer, err := agent.NewRequestSigner(agent.SignerOptions{
		AgentID:   "aauth:demo-agent@agents.example.com",
		KeyID:     "demo-key-1",
		Signer:    priv,
		Algorithm: "ed25519",
		Tokens:    &agent.TokenStore{AgentToken: "<aa-agent+jwt token>"},
	})
	if err != nil {
		return
	}

	client := &http.Client{
		Transport: transport.NewSigningTransport(
			http.DefaultTransport,
			signer,
			[]string{"@method", "@authority", "@path", "signature-key"},
		),
	}

	req, err := http.NewRequest(http.MethodGet, "https://api.example.com/data", nil)
	if err != nil {
		return
	}
	_, _ = client.Do(req)
}
