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

type AgentTokenClaims struct {
	Iss    string `json:"iss"`
	Dwk    string `json:"dwk"`
	Sub    string `json:"sub"` // Agent identifier
	Aud    string `json:"aud"`
	Iat    int64  `json:"iat"`
	Exp    int64  `json:"exp"`
	CnfJWK string `json:"-"` // RFC 7638 thumbprint of cnf.jwk
}

func ParseAndVerifyAgentToken(token string, set jwk.Set, expectedAud string, allowInsecureISS bool) (*AgentTokenClaims, error) {
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
	if typ != "aa-agent+jwt" {
		return nil, fmt.Errorf("%w: expected typ=aa-agent+jwt, got %s", ErrInvalidJWT, typ)
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

	claims := &AgentTokenClaims{}
	claims.Iss, _ = claimsMap["iss"].(string)
	claims.Dwk, _ = claimsMap["dwk"].(string)
	claims.Sub, _ = claimsMap["sub"].(string)
	claims.Aud, _ = claimsMap["aud"].(string)

	if iat, ok := claimsMap["iat"].(float64); ok {
		claims.Iat = int64(iat)
	}
	if exp, ok := claimsMap["exp"].(float64); ok {
		claims.Exp = int64(exp)
	}

	// 4. Validate dwk.
	if claims.Dwk != "aauth-agent.json" {
		return nil, fmt.Errorf("%w: expected dwk=aauth-agent.json, got %s", ErrInvalidJWT, claims.Dwk)
	}

	// 5. Validate iss (https by default; optional local http when allowInsecureISS).
	if !issAllowedInAAuthJWT(claims.Iss, allowInsecureISS) {
		if !allowInsecureISS {
			return nil, fmt.Errorf("%w: iss must be an HTTPS URL", ErrInvalidJWT)
		}
		return nil, fmt.Errorf("%w: iss must be https, or http for a local development host when allow_insecure_jwt_issuer is true", ErrInvalidJWT)
	}

	// 6. Validate iat (must not be in the future beyond a small skew).
	const clockSkew = 5 * time.Second
	now := time.Now()
	if claims.Iat > 0 && time.Unix(claims.Iat, 0).After(now.Add(clockSkew)) {
		return nil, fmt.Errorf("%w: iat is in the future", ErrInvalidJWT)
	}

	// 7. Validate exp.
	if claims.Exp > 0 && now.Unix() > claims.Exp {
		return nil, ErrExpiredJWT
	}

	// 8. Optional audience. Per AAuth, aa-auth+jwt binds to a resource via aud; aa-agent+jwt
	// is issued for agent identity and typically has no aud (AAuth-Identity / signing mode). If
	// present, must equal this resource's issuer (RFC 7519 aud: string or array of strings).
	if err := checkAgentTokenAudience(claimsMap, expectedAud); err != nil {
		return nil, err
	}

	// 9. Extract RFC 7638 thumbprint from cnf.jwk.
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

// checkAgentTokenAudience enforces that aa-agent+jwt "aud" is either absent, empty, or
// includes this resource's issuer. Unlike aa-auth+jwt, agent tokens are not
// resource-scoped by default (see aauth-extauthz-plan: auth tokens verify aud).
func checkAgentTokenAudience(claimsMap map[string]interface{}, expected string) error {
	v, ok := claimsMap["aud"]
	if !ok || v == nil {
		return nil
	}
	switch t := v.(type) {
	case string:
		if t == "" {
			return nil
		}
		if t == expected {
			return nil
		}
		return fmt.Errorf("%w: audience mismatch: got %s, expected %s", ErrInvalidToken, t, expected)
	case []interface{}:
		if len(t) == 0 {
			return nil
		}
		for _, x := range t {
			if s, ok := x.(string); ok && s == expected {
				return nil
			}
		}
		return fmt.Errorf("%w: audience mismatch: got no matching entry for %s", ErrInvalidToken, expected)
	default:
		return fmt.Errorf("%w: aud must be a string or array of strings", ErrInvalidJWT)
	}
}
