package aauth

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

type AuthTokenClaims struct {
	Iss    string `json:"iss"`
	Sub    string `json:"sub"` // Delegate
	Aud    string `json:"aud"`
	Exp    int64  `json:"exp"`
	Agent  string `json:"agent"`
	Scope  string `json:"scope"`
	Txn    string `json:"txn"`
	CnfJWK string `json:"-"` // Thumbprint of cnf.jwk
}

func ParseAndVerifyAuthToken(token string, set jwk.Set, expectedAud string) (*AuthTokenClaims, error) {
	header, claimsMap, err := parseJWTUnverified(token)
	if err != nil {
		return nil, ErrInvalidJWT
	}

	typ, _ := header["typ"].(string)
	if typ != "auth+jwt" {
		return nil, fmt.Errorf("%w: expected typ=auth+jwt", ErrInvalidJWT)
	}

	// In a real implementation we would:
	// 1. Verify the JWT signature using `set`
	// 2. Validate standard claims (exp, etc.)

	claims := &AuthTokenClaims{}
	claims.Iss, _ = claimsMap["iss"].(string)
	claims.Sub, _ = claimsMap["sub"].(string)
	claims.Aud, _ = claimsMap["aud"].(string)
	claims.Agent, _ = claimsMap["agent"].(string)
	claims.Scope, _ = claimsMap["scope"].(string)
	claims.Txn, _ = claimsMap["txn"].(string)

	if exp, ok := claimsMap["exp"].(float64); ok {
		claims.Exp = int64(exp)
	}

	// Verify audience matches Resource.Issuer
	if claims.Aud != expectedAud {
		return nil, fmt.Errorf("%w: audience mismatch", ErrInvalidToken)
	}

	if now := time.Now().Unix(); claims.Exp > 0 && now > claims.Exp {
		return nil, ErrExpiredJWT
	}

	if cnf, ok := claimsMap["cnf"].(map[string]interface{}); ok {
		if jwkMap, ok := cnf["jwk"].(map[string]interface{}); ok {
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
