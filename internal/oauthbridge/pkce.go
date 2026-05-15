package oauthbridge

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// NewPKCEPair generates a PKCE code_verifier and the corresponding code_challenge
// (S256 method, per RFC 7636).
func NewPKCEPair() (verifier, challenge string) {
	raw := make([]byte, 32)
	rand.Read(raw) //nolint:errcheck
	verifier = base64.RawURLEncoding.EncodeToString(raw)
	h := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h[:])
	return verifier, challenge
}
