package aauth

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

type AgentTokenClaims struct {
	Iss    string `json:"iss"`
	Sub    string `json:"sub"` // Delegate
	Aud    string `json:"aud"`
	Exp    int64  `json:"exp"`
	CnfJWK string `json:"-"` // Thumbprint of cnf.jwk
}

func ParseAndVerifyAgentToken(token string, set jwk.Set) (*AgentTokenClaims, error) {
	header, claimsMap, err := parseJWTUnverified(token)
	if err != nil {
		return nil, ErrInvalidJWT
	}

	typ, _ := header["typ"].(string)
	if typ != "agent+jwt" {
		return nil, fmt.Errorf("%w: expected typ=agent+jwt", ErrInvalidJWT)
	}

	// In a real implementation we would:
	// 1. Verify the JWT signature using `set`
	// 2. Validate standard claims (exp, etc.)

	// For now, extract claims
	claims := &AgentTokenClaims{}
	claims.Iss, _ = claimsMap["iss"].(string)
	claims.Sub, _ = claimsMap["sub"].(string)
	claims.Aud, _ = claimsMap["aud"].(string)
	if exp, ok := claimsMap["exp"].(float64); ok {
		claims.Exp = int64(exp)
	}

	if now := time.Now().Unix(); claims.Exp > 0 && now > claims.Exp {
		return nil, ErrExpiredJWT
	}

	if cnf, ok := claimsMap["cnf"].(map[string]interface{}); ok {
		if jwkMap, ok := cnf["jwk"].(map[string]interface{}); ok {
			// Convert to jwk.Key to calculate thumbprint
			b, err := json.Marshal(jwkMap)
			if err == nil {
				if key, err := jwk.ParseKey(b); err == nil {
					tp, _ := key.Thumbprint(crypto.SHA256)
					claims.CnfJWK = base64.RawURLEncoding.EncodeToString(tp)
				}
			}
		}
	}

	return claims, nil
}
