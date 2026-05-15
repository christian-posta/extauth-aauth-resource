// Package wrappedtoken handles AES-256-GCM encryption of OAuth tokens into
// the opaque blob carried in the AAuth-Access response header (AAuth spec §704).
//
// Format: base64url(nonce[12] || gcm_ciphertext_and_tag)
// AAD:    []byte(resourceID)  — prevents cross-resource token reuse
//
// The plaintext is JSON-encoded Token.
package wrappedtoken

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// Token is the plaintext stored inside the opaque AAuth-Access blob.
type Token struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
	Scope        string    `json:"scope,omitempty"`
	AgentJKT     string    `json:"agent_jkt"` // binding: must match the presenting agent
	IssuedAt     time.Time `json:"issued_at"`
}

// IsExpired reports whether the access token is past its expiry.
// Tokens with zero ExpiresAt are treated as non-expiring.
func (t *Token) IsExpired() bool {
	if t.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(t.ExpiresAt)
}

// ExpiresWithin reports whether the token expires within the given duration.
func (t *Token) ExpiresWithin(d time.Duration) bool {
	if t.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().Add(d).After(t.ExpiresAt)
}

// Wrap encrypts tok into an opaque string using key, with resourceID as AAD.
// key must be exactly 32 bytes (AES-256).
func Wrap(tok Token, resourceID string, key []byte) (string, error) {
	if len(key) != 32 {
		return "", fmt.Errorf("wrappedtoken: key must be 32 bytes, got %d", len(key))
	}
	plaintext, err := json.Marshal(tok)
	if err != nil {
		return "", fmt.Errorf("wrappedtoken: marshal: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("wrappedtoken: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("wrappedtoken: new gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("wrappedtoken: rand nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, []byte(resourceID))
	return base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

// Unwrap decrypts the opaque string produced by Wrap.
// It verifies that resourceID matches the AAD used during encryption.
func Unwrap(opaque, resourceID string, key []byte) (Token, error) {
	if len(key) != 32 {
		return Token{}, fmt.Errorf("wrappedtoken: key must be 32 bytes, got %d", len(key))
	}
	raw, err := base64.RawURLEncoding.DecodeString(opaque)
	if err != nil {
		return Token{}, fmt.Errorf("wrappedtoken: base64 decode: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return Token{}, fmt.Errorf("wrappedtoken: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return Token{}, fmt.Errorf("wrappedtoken: new gcm: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(raw) < nonceSize {
		return Token{}, fmt.Errorf("wrappedtoken: ciphertext too short")
	}
	nonce, ct := raw[:nonceSize], raw[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ct, []byte(resourceID))
	if err != nil {
		return Token{}, fmt.Errorf("wrappedtoken: decrypt: %w", err)
	}

	var tok Token
	if err := json.Unmarshal(plaintext, &tok); err != nil {
		return Token{}, fmt.Errorf("wrappedtoken: unmarshal: %w", err)
	}
	return tok, nil
}
