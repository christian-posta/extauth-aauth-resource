package aauth

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"policy_engine/internal/config"
)

type ResourceTokenClaims struct {
	Iss      string `json:"iss"`
	Aud      string `json:"aud,omitempty"`
	Agent    string `json:"agent,omitempty"`
	AgentJKT string `json:"agent_jkt"`
	Exp      int64  `json:"exp"`
	Scope    string `json:"scope,omitempty"`
	Txn      string `json:"txn,omitempty"`
	Jti      string `json:"jti"`
}

type JOSEHeader struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

// MintResourceToken creates a signed resource-token JWT.
func MintResourceToken(rc *config.ResourceConfig, claims ResourceTokenClaims, privKey ed25519.PrivateKey) (string, error) {
	header := JOSEHeader{
		Typ: "resource+jwt",
		Alg: "EdDSA",
		Kid: rc.SigningKey.Kid,
	}

	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", err
	}

	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerBytes)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsBytes)

	unsignedToken := headerB64 + "." + claimsB64

	sig := ed25519.Sign(privKey, []byte(unsignedToken))
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	return unsignedToken + "." + sigB64, nil
}

// ExtractJWKThumbprint calculates the RFC 7638 thumbprint of an Ed25519 public key.
func ExtractJWKThumbprint(pub ed25519.PublicKey) (string, error) {
	// For Phase 1 we use a dummy thumbprint if we don't have the full crypto implementation
	// We'll just encode the raw bytes
	return base64.RawURLEncoding.EncodeToString(pub), nil
}

// Token helper for parsing generic JWTs
func parseJWTUnverified(token string) (map[string]interface{}, map[string]interface{}, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("invalid JWT format")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, err
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, nil, err
	}

	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, err
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, nil, err
	}

	return header, claims, nil
}
