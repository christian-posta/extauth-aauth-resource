package aauth

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

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
	// 1. Extract raw signature headers.
	if len(headers["signature"]) == 0 || len(headers["signature-input"]) == 0 || len(headers["signature-key"]) == 0 {
		return VerifyResult{Err: ErrMissingSignature}
	}

	// 2. Parse Signature-Key.
	sigKeyStr := strings.Join(headers["signature-key"], ", ")
	parsedKey, err := sigkey.Parse(sigKeyStr)
	if err != nil {
		return VerifyResult{Err: ErrInvalidSignature}
	}

	var pubKey ed25519.PublicKey
	var identity Identity

	switch parsedKey.Scheme {
	case sigkey.SchemeHWK:
		// Non-standard pseudonymous extension: inline bare key.
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
		pub := ed25519.PublicKey(xBytes)

		jkt, jktErr := ExtractJWKThumbprint(pub)
		if jktErr != nil {
			return VerifyResult{Err: ErrInvalidKey}
		}
		identity.JKT = jkt

		if !rc.AllowPseudonymous {
			// Level too low — return identity so a bound resource-token can be minted.
			identity.Level = LevelPseudonymous
			return VerifyResult{Identity: identity, Err: ErrInsufficientScope}
		}

		pubKey = pub
		identity.Level = LevelPseudonymous

	case sigkey.SchemeJWKSURI:
		if jwksClient == nil {
			return VerifyResult{Err: ErrInvalidKey}
		}

		// Verify the JWKS URI belongs to a known agent server.
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
			return VerifyResult{Err: ErrInvalidKey}
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

		// Peek at the JWT header to get typ and iss before verifying.
		jwtHeader, jwtClaimsMap, err := parseJWTUnverified(parsedKey.JWT)
		if err != nil {
			return VerifyResult{Err: ErrInvalidJWT}
		}

		typ, _ := jwtHeader["typ"].(string)
		iss, _ := jwtClaimsMap["iss"].(string)
		dwk, _ := jwtClaimsMap["dwk"].(string)

		if typ == "aa-agent+jwt" {
			// Verify the issuer is a known agent server (SSRF protection).
			var knownAgentServer bool
			for _, as := range rc.AgentServers {
				if as.Issuer == iss {
					knownAgentServer = true
					break
				}
			}
			if !knownAgentServer {
				return VerifyResult{Err: ErrInvalidJWT}
			}

			// Discover JWKS via {iss}/.well-known/{dwk} per AAuth spec.
			if dwk == "" {
				return VerifyResult{Err: ErrInvalidJWT}
			}
			discoveryURL := strings.TrimRight(iss, "/") + "/.well-known/" + dwk

			set, err := jwksClient.Get(context.Background(), discoveryURL)
			if err != nil {
				return VerifyResult{Err: ErrInvalidKey}
			}

			agentClaims, err := ParseAndVerifyAgentToken(parsedKey.JWT, set)
			if err != nil {
				return VerifyResult{Err: err}
			}

			// The HTTP request must be signed with the key bound in cnf.jwk.
			pubKey = extractEd25519FromCnf(jwtClaimsMap)
			if pubKey == nil {
				return VerifyResult{Err: ErrInvalidKey}
			}

			identity.Level = LevelIdentified
			identity.AgentServer = iss
			identity.Delegate = agentClaims.Sub
			identity.JKT = agentClaims.CnfJWK

		} else if typ == "aa-auth+jwt" {
			// Verify the issuer is a known auth server (SSRF protection).
			var knownAuthServer bool
			for _, as := range rc.AuthServers {
				if as.Issuer == iss {
					knownAuthServer = true
					break
				}
			}
			if !knownAuthServer {
				return VerifyResult{Err: ErrInvalidJWT}
			}

			// Discover JWKS via {iss}/.well-known/{dwk} per AAuth spec.
			if dwk == "" {
				return VerifyResult{Err: ErrInvalidJWT}
			}
			discoveryURL := strings.TrimRight(iss, "/") + "/.well-known/" + dwk

			set, err := jwksClient.Get(context.Background(), discoveryURL)
			if err != nil {
				return VerifyResult{Err: ErrInvalidKey}
			}

			authClaims, err := ParseAndVerifyAuthToken(parsedKey.JWT, set, rc.Issuer)
			if err != nil {
				return VerifyResult{Err: err}
			}

			// The HTTP request must be signed with the key bound in cnf.jwk.
			pubKey = extractEd25519FromCnf(jwtClaimsMap)
			if pubKey == nil {
				return VerifyResult{Err: ErrInvalidKey}
			}

			// Verify act.sub matches cnf.jwk thumbprint (the agent's signing key identity).
			if authClaims.Act == nil || authClaims.Act.Sub != authClaims.CnfJWK {
				return VerifyResult{Err: ErrInvalidToken}
			}

			// Verify agent is a non-empty HTTPS URL and (if configured) matches a known agent server.
			if authClaims.Agent == "" || !strings.HasPrefix(authClaims.Agent, "https://") {
				return VerifyResult{Err: ErrInvalidToken}
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

	// 4. HTTPSig verify.
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
		if errors.Is(err, httpsig.ErrMissingSignatureKeyCoverage) {
			return VerifyResult{Err: ErrInvalidSignature}
		}
		if errors.Is(err, httpsig.ErrUnsupportedAlgorithm) {
			return VerifyResult{Err: ErrUnsupportedAlgorithm}
		}
		return VerifyResult{Err: ErrInvalidSignature}
	}

	return VerifyResult{Identity: identity, Err: nil}
}

// extractEd25519FromCnf pulls the Ed25519 public key from a JWT's cnf.jwk claim map.
func extractEd25519FromCnf(claimsMap map[string]interface{}) ed25519.PublicKey {
	cnf, ok := claimsMap["cnf"].(map[string]interface{})
	if !ok {
		return nil
	}
	jwkMap, ok := cnf["jwk"].(map[string]interface{})
	if !ok {
		return nil
	}
	b, err := json.Marshal(jwkMap)
	if err != nil {
		return nil
	}
	key, err := jwk.ParseKey(b)
	if err != nil {
		return nil
	}
	var rawKey interface{}
	if err := key.Raw(&rawKey); err != nil {
		return nil
	}
	edKey, ok := rawKey.(ed25519.PublicKey)
	if !ok {
		return nil
	}
	return edKey
}
