package aauth

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

// Act represents the RFC 8693 actor claim, which identifies the party that
// requested the token and chains delegation.
type Act struct {
	Sub string `json:"sub"`
}

type AuthTokenClaims struct {
	Iss    string `json:"iss"`
	Dwk    string `json:"dwk"`
	Sub    string `json:"sub"`
	Aud    string `json:"aud"`
	Agent  string `json:"agent"`
	Scope  string `json:"scope"`
	Txn    string `json:"txn"`
	Iat    int64  `json:"iat"`
	Exp    int64  `json:"exp"`
	Act    *Act   `json:"act,omitempty"`
	CnfJWK string `json:"-"` // RFC 7638 thumbprint of cnf.jwk
}

func ParseAndVerifyAuthToken(token string, set jwk.Set, expectedAud string) (*AuthTokenClaims, error) {
	// 1. Decode header without verifying to check typ first.
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
	if typ != "aa-auth+jwt" {
		return nil, fmt.Errorf("%w: expected typ=aa-auth+jwt, got %s", ErrInvalidJWT, typ)
	}

	// 2. Verify signature using the provided JWKS.
	payload, err := jws.Verify([]byte(token), jws.WithKeySet(set, jws.WithInferAlgorithmFromKey(true)))
	if err != nil {
		return nil, fmt.Errorf("%w: signature verification failed: %v", ErrInvalidSignature, err)
	}

	// 3. Unmarshal verified payload.
	var claimsMap map[string]interface{}
	if err := json.Unmarshal(payload, &claimsMap); err != nil {
		return nil, ErrInvalidJWT
	}

	claims := &AuthTokenClaims{}
	claims.Iss, _ = claimsMap["iss"].(string)
	claims.Dwk, _ = claimsMap["dwk"].(string)
	claims.Sub, _ = claimsMap["sub"].(string)
	claims.Aud, _ = claimsMap["aud"].(string)
	claims.Agent, _ = claimsMap["agent"].(string)
	claims.Scope, _ = claimsMap["scope"].(string)
	claims.Txn, _ = claimsMap["txn"].(string)

	if iat, ok := claimsMap["iat"].(float64); ok {
		claims.Iat = int64(iat)
	}
	if exp, ok := claimsMap["exp"].(float64); ok {
		claims.Exp = int64(exp)
	}

	// 4. Extract act claim.
	if actMap, ok := claimsMap["act"].(map[string]interface{}); ok {
		sub, _ := actMap["sub"].(string)
		claims.Act = &Act{Sub: sub}
	}

	// 5. Validate dwk.
	if claims.Dwk != "aauth-access.json" && claims.Dwk != "aauth-person.json" {
		return nil, fmt.Errorf("%w: expected dwk=aauth-access.json or aauth-person.json, got %s", ErrInvalidJWT, claims.Dwk)
	}

	// 6. Validate iss is HTTPS.
	if !strings.HasPrefix(claims.Iss, "https://") {
		return nil, fmt.Errorf("%w: iss must be an HTTPS URL", ErrInvalidJWT)
	}

	// 7. Validate iat.
	const clockSkew = 5 * time.Second
	now := time.Now()
	if claims.Iat > 0 && time.Unix(claims.Iat, 0).After(now.Add(clockSkew)) {
		return nil, fmt.Errorf("%w: iat is in the future", ErrInvalidJWT)
	}

	// 8. Validate exp.
	if claims.Exp > 0 && now.Unix() > claims.Exp {
		return nil, ErrExpiredJWT
	}

	// 9. Validate audience.
	if claims.Aud != expectedAud {
		return nil, fmt.Errorf("%w: audience mismatch: got %s, expected %s", ErrInvalidToken, claims.Aud, expectedAud)
	}

	// 10. Validate act is present.
	if claims.Act == nil || claims.Act.Sub == "" {
		return nil, fmt.Errorf("%w: act.sub is required", ErrInvalidToken)
	}

	// 11. Extract RFC 7638 thumbprint from cnf.jwk.
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
