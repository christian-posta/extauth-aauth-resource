package aauth

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/lestrrat-go/jwx/v2/jwk"

	"policy_engine/internal/config"
	"policy_engine/pkg/httpsig"
	"policy_engine/pkg/sigkey"
)

type jwksFetcher interface {
	Get(ctx context.Context, uri string) (jwk.Set, error)
}

type VerifyResult struct {
	Identity Identity
	Err      error
}

func Verify(rc *config.ResourceConfig, method, authority, path string, headers map[string][]string, jwksClient jwksFetcher) VerifyResult {
	// 1. Extract raw signature headers
	if len(headers["signature"]) == 0 || len(headers["signature-input"]) == 0 || len(headers["signature-key"]) == 0 {
		return VerifyResult{Err: ErrMissingSignature}
	}

	// 2. Parse Signature-Key
	sigKeyStr := ""
	for i, v := range headers["signature-key"] {
		if i > 0 {
			sigKeyStr += ", "
		}
		sigKeyStr += v
	}

	parsedKey, err := sigkey.Parse(sigKeyStr)
	if err != nil {
		return VerifyResult{Err: ErrInvalidSignature}
	}

	// 3. Resolve verification key based on scheme (only HWK for Phase 1)
	var pubKey ed25519.PublicKey
	var identity Identity

	switch parsedKey.Scheme {
	case sigkey.SchemeHWK:
		if !rc.AllowPseudonymous {
			// They sent HWK but we don't allow pseudonymous. We need to 401 them
			// and tell them to get an auth-token.
			// Return a special error to trigger the challenge.
			identity.Level = LevelPseudonymous

			// Extract JKT for resource token binding
			kty, _ := parsedKey.HWK["kty"].(string)
			crv, _ := parsedKey.HWK["crv"].(string)
			x, _ := parsedKey.HWK["x"].(string)

			if kty == "OKP" && crv == "Ed25519" && x != "" {
				xBytes, err := base64.RawURLEncoding.DecodeString(x)
				if err == nil && len(xBytes) == ed25519.PublicKeySize {
					pub := ed25519.PublicKey(xBytes)
					jkt, _ := ExtractJWKThumbprint(pub)
					identity.JKT = jkt
				}
			}

			return VerifyResult{Identity: identity, Err: ErrInsufficientScope} // Reusing ErrInsufficientScope as a "level too low" indicator for now
		}

		kty, _ := parsedKey.HWK["kty"].(string)
		crv, _ := parsedKey.HWK["crv"].(string)
		x, _ := parsedKey.HWK["x"].(string)

		if kty != "OKP" || crv != "Ed25519" || x == "" {
			return VerifyResult{Err: ErrUnsupportedAlgorithm}
		}

		xBytes, err := base64.RawURLEncoding.DecodeString(x)
		if err != nil || len(xBytes) != ed25519.PublicKeySize {
			return VerifyResult{Err: ErrInvalidKey}
		}
		pubKey = ed25519.PublicKey(xBytes)
		identity.Level = LevelPseudonymous

	case sigkey.SchemeJWKSURI:
		if jwksClient == nil {
			return VerifyResult{Err: ErrInvalidKey}
		}

		// Verify the issuer is an allowed agent server
		var agentServer string
		for _, as := range rc.AgentServers {
			if as.JwksURI == parsedKey.JWKSURI {
				agentServer = as.Issuer
				break
			}
		}

		if agentServer == "" {
			return VerifyResult{Err: ErrInvalidKey}
		}

		set, err := jwksClient.Get(context.Background(), parsedKey.JWKSURI)
		if err != nil {
			return VerifyResult{Err: ErrInvalidKey}
		}

		if parsedKey.KeyID == "" {
			return VerifyResult{Err: ErrInvalidKey} // kid is mandatory for jwks_uri
		}

		key, ok := set.LookupKeyID(parsedKey.KeyID)
		if !ok {
			return VerifyResult{Err: ErrUnknownKey}
		}

		var rawKey interface{}
		if err := key.Raw(&rawKey); err != nil {
			return VerifyResult{Err: ErrInvalidKey}
		}

		edKey, ok := rawKey.(ed25519.PublicKey)
		if !ok {
			return VerifyResult{Err: ErrUnsupportedAlgorithm}
		}

		pubKey = edKey
		identity.Level = LevelIdentified
		identity.AgentServer = agentServer

		jktBytes, _ := key.Thumbprint(crypto.SHA256)
		identity.JKT = base64.RawURLEncoding.EncodeToString(jktBytes)

	case sigkey.SchemeJWT:
		if jwksClient == nil {
			return VerifyResult{Err: ErrInvalidKey}
		}

		// First parse the JWT unverified to get the issuer
		header, claimsMap, err := parseJWTUnverified(parsedKey.JWT)
		if err != nil {
			return VerifyResult{Err: ErrInvalidJWT}
		}

		typ, _ := header["typ"].(string)
		iss, _ := claimsMap["iss"].(string)

		if typ == "agent+jwt" {
			var jwksURI string
			for _, as := range rc.AgentServers {
				if as.Issuer == iss {
					jwksURI = as.JwksURI
					break
				}
			}

			if jwksURI == "" {
				return VerifyResult{Err: ErrInvalidJWT}
			}

			set, err := jwksClient.Get(context.Background(), jwksURI)
			if err != nil {
				return VerifyResult{Err: ErrInvalidKey}
			}

			agentClaims, err := ParseAndVerifyAgentToken(parsedKey.JWT, set)
			if err != nil {
				return VerifyResult{Err: err}
			}

			// We need a public key for HTTPSig verification
			// For JWT scheme, the key used to sign the HTTP request MUST match cnf.jwk
			// We haven't verified the signature yet, so we don't have the pubkey.
			// Actually, the sender must embed the public key in the Signature-Key header params too?
			// No, the spec says for JWT scheme, the cnf.jwk is the verification key.

			// Let's decode cnf.jwk from the token and use it as pubKey
			if cnf, ok := claimsMap["cnf"].(map[string]interface{}); ok {
				if jwkMap, ok := cnf["jwk"].(map[string]interface{}); ok {
					b, _ := json.Marshal(jwkMap)
					if key, err := jwk.ParseKey(b); err == nil {
						var rawKey interface{}
						if err := key.Raw(&rawKey); err == nil {
							if edKey, ok := rawKey.(ed25519.PublicKey); ok {
								pubKey = edKey
							}
						}
					}
				}
			}

			if pubKey == nil {
				return VerifyResult{Err: ErrInvalidKey}
			}

			identity.Level = LevelIdentified
			identity.AgentServer = iss
			identity.Delegate = agentClaims.Sub
			identity.JKT = agentClaims.CnfJWK
		} else if typ == "auth+jwt" {
			var jwksURI string
			for _, as := range rc.AuthServers {
				if as.Issuer == iss {
					jwksURI = as.JwksURI
					break
				}
			}

			if jwksURI == "" {
				return VerifyResult{Err: ErrInvalidJWT}
			}

			set, err := jwksClient.Get(context.Background(), jwksURI)
			if err != nil {
				return VerifyResult{Err: ErrInvalidKey}
			}

			authClaims, err := ParseAndVerifyAuthToken(parsedKey.JWT, set, rc.Issuer)
			if err != nil {
				return VerifyResult{Err: err}
			}

			if cnf, ok := claimsMap["cnf"].(map[string]interface{}); ok {
				if jwkMap, ok := cnf["jwk"].(map[string]interface{}); ok {
					b, _ := json.Marshal(jwkMap)
					if key, err := jwk.ParseKey(b); err == nil {
						var rawKey interface{}
						if err := key.Raw(&rawKey); err == nil {
							if edKey, ok := rawKey.(ed25519.PublicKey); ok {
								pubKey = edKey
							}
						}
					}
				}
			}

			if pubKey == nil {
				return VerifyResult{Err: ErrInvalidKey}
			}

			identity.Level = LevelAuthorized
			identity.AgentServer = authClaims.Agent
			identity.Delegate = authClaims.Sub
			identity.Scope = authClaims.Scope
			identity.Txn = authClaims.Txn
			identity.JKT = authClaims.CnfJWK
		} else {
			return VerifyResult{Err: ErrUnsupportedScheme}
		}

	default:
		return VerifyResult{Err: ErrUnsupportedScheme}
	}

	// 4. HTTPSig verify
	reqComps := []string{"@method", "@authority", "@path", "signature-key"}
	reqComps = append(reqComps, rc.AdditionalSignatureComponents...)

	vIn := httpsig.VerifyInput{
		Method:             method,
		Authority:          authority,
		Path:               path,
		Headers:            headers,
		RequiredComponents: reqComps,
		AllowedAlgs:        []string{"ed25519"},
		MaxClockSkew:       rc.SignatureWindow,
		PublicKey:          pubKey,
		Alg:                "ed25519",
	}

	_, err = httpsig.Verify(vIn)
	if err != nil {
		if errors.Is(err, httpsig.ErrMissingSignature) {
			return VerifyResult{Err: ErrMissingSignature}
		}
		if errors.Is(err, httpsig.ErrUnsupportedAlgorithm) {
			return VerifyResult{Err: ErrUnsupportedAlgorithm}
		}
		return VerifyResult{Err: ErrInvalidSignature}
	}

	return VerifyResult{Identity: identity, Err: nil}
}
