package aauth

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"

	"aauth-service/internal/config"
)

type ResourceTokenClaims struct {
	Iss      string `json:"iss"`
	Dwk      string `json:"dwk"`
	Aud      string `json:"aud,omitempty"`
	Agent    string `json:"agent,omitempty"`
	AgentJKT string `json:"agent_jkt"`
	Iat      int64  `json:"iat"`
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

// ResolveResourceTokenAud returns the configured audience for resource tokens.
// Mode 3 pins this to the configured Person Server issuer.
func ResolveResourceTokenAud(rc *config.ResourceConfig) string {
	if rc == nil {
		return ""
	}
	if rc.PersonServer.Issuer != "" {
		return rc.PersonServer.Issuer
	}
	return ""
}

func ParseAndVerifyResourceToken(token string, set jwk.Set, expectedAud string, allowInsecureISS bool) (*ResourceTokenClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidJWT
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrInvalidJWT
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, ErrInvalidJWT
	}
	typ, _ := header["typ"].(string)
	if typ != "aa-resource+jwt" {
		return nil, fmt.Errorf("%w: expected typ=aa-resource+jwt, got %s", ErrInvalidJWT, typ)
	}

	payload, err := jws.Verify([]byte(token), jws.WithKeySet(set, jws.WithInferAlgorithmFromKey(true)))
	if err != nil {
		return nil, fmt.Errorf("%w: signature verification failed: %v", ErrInvalidSignature, err)
	}

	var claims ResourceTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, ErrInvalidJWT
	}
	if claims.Dwk != "aauth-resource.json" {
		return nil, fmt.Errorf("%w: expected dwk=aauth-resource.json, got %s", ErrInvalidJWT, claims.Dwk)
	}
	if !issAllowedInAAuthJWT(claims.Iss, allowInsecureISS) {
		if !allowInsecureISS {
			return nil, fmt.Errorf("%w: iss must be an HTTPS URL", ErrInvalidJWT)
		}
		return nil, fmt.Errorf("%w: iss must be https, or http for a local development host when allow_insecure_jwt_issuer is true", ErrInvalidJWT)
	}
	now := time.Now()
	if claims.Iat > 0 && time.Unix(claims.Iat, 0).After(now.Add(5*time.Second)) {
		return nil, fmt.Errorf("%w: iat is in the future", ErrInvalidJWT)
	}
	if claims.Exp > 0 && now.Unix() > claims.Exp {
		return nil, ErrExpiredJWT
	}
	if expectedAud != "" && claims.Aud != expectedAud {
		return nil, fmt.Errorf("%w: audience mismatch: got %s, expected %s", ErrInvalidToken, claims.Aud, expectedAud)
	}
	if claims.AgentJKT == "" {
		return nil, fmt.Errorf("%w: agent_jkt is required", ErrInvalidToken)
	}
	return &claims, nil
}

// newJTI generates a random UUID v4 string for use as a JWT jti claim.
func newJTI() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// MintResourceToken creates a signed resource-token JWT.
func MintResourceToken(rc *config.ResourceConfig, claims ResourceTokenClaims, privKey ed25519.PrivateKey) (string, error) {
	// Set mandatory fields that the caller should not have to think about.
	claims.Dwk = "aauth-resource.json"
	if claims.Iat == 0 {
		claims.Iat = time.Now().Unix()
	}
	if claims.Jti == "" {
		claims.Jti = newJTI()
	}

	header := JOSEHeader{
		Typ: "aa-resource+jwt",
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

// ExtractJWKThumbprint calculates the RFC 7638 JWK Thumbprint of an Ed25519 public key.
func ExtractJWKThumbprint(pub ed25519.PublicKey) (string, error) {
	key, err := jwk.FromRaw(pub)
	if err != nil {
		return "", fmt.Errorf("failed to create JWK: %w", err)
	}
	tp, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("failed to compute thumbprint: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(tp), nil
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
