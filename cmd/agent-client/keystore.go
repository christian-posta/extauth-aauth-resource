package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
)

// keystore persists Ed25519 keys + their kids across runs so the JWKS the
// agent-client publishes stays stable. The aauth-service's JWKS cache has a
// 60-second min-refetch window, so freshly generated keys on every run would
// otherwise fail kid lookup. This is a demo convenience, not a hardened
// secret store — keys are written in cleartext.
type keystore struct {
	RequestKID     string `json:"request_kid"`
	RequestPubB64  string `json:"request_pub"`
	RequestPrivB64 string `json:"request_priv"`

	AgentServerKID     string `json:"agent_server_kid"`
	AgentServerPubB64  string `json:"agent_server_pub"`
	AgentServerPrivB64 string `json:"agent_server_priv"`
}

func loadOrCreateKeystore(path string) (*keystore, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		ks := &keystore{}
		if err := json.Unmarshal(data, ks); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		log.Printf("loaded keys from %s (request kid=%s, agent-server kid=%s)", path, ks.RequestKID, ks.AgentServerKID)
		return ks, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	reqPub, reqPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate request key: %w", err)
	}
	asPub, asPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate agent-server key: %w", err)
	}
	ks := &keystore{
		RequestKID:         "req-" + shortID(),
		RequestPubB64:      base64.StdEncoding.EncodeToString(reqPub),
		RequestPrivB64:     base64.StdEncoding.EncodeToString(reqPriv),
		AgentServerKID:     "agentserver-" + shortID(),
		AgentServerPubB64:  base64.StdEncoding.EncodeToString(asPub),
		AgentServerPrivB64: base64.StdEncoding.EncodeToString(asPriv),
	}
	out, err := json.MarshalIndent(ks, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return nil, fmt.Errorf("write %s: %w", path, err)
	}
	log.Printf("generated and saved keys to %s (request kid=%s, agent-server kid=%s)", path, ks.RequestKID, ks.AgentServerKID)
	return ks, nil
}

func (k *keystore) RequestPub() ed25519.PublicKey {
	b, _ := base64.StdEncoding.DecodeString(k.RequestPubB64)
	return ed25519.PublicKey(b)
}

func (k *keystore) RequestPriv() ed25519.PrivateKey {
	b, _ := base64.StdEncoding.DecodeString(k.RequestPrivB64)
	return ed25519.PrivateKey(b)
}

func (k *keystore) AgentServerPub() ed25519.PublicKey {
	b, _ := base64.StdEncoding.DecodeString(k.AgentServerPubB64)
	return ed25519.PublicKey(b)
}

func (k *keystore) AgentServerPriv() ed25519.PrivateKey {
	b, _ := base64.StdEncoding.DecodeString(k.AgentServerPrivB64)
	return ed25519.PrivateKey(b)
}
