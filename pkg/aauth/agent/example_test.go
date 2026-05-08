package agent_test

import (
	"crypto/ed25519"
	"crypto/rand"

	"aauth-service/pkg/aauth/agent"
)

func ExampleNewRequestSigner() {
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

	// signer.Sign(ctx, req, []string{"@method", "@authority", "@path", "signature-key"})
	_ = signer.Scheme()
}
