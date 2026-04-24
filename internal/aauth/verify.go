package aauth

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwk"

	"aauth-service/internal/config"
	"aauth-service/pkg/httpsig"
	"aauth-service/pkg/sigkey"
)

// aauthJWKSErr carries a diagnostic stage for AAuth well-known -> jwks_uri -> JWKS loading.
type aauthJWKSErr struct {
	Stage  string
	Detail string
}

func (e *aauthJWKSErr) Error() string { return e.Detail }

// loadAAuthJWKSSet fetches the issuer's well-known metadata, reads jwks_uri, optionally
// checks it against a configured pin, then loads the JWK set. Per SPEC.md §4 (metadata)
// and §12.10, tokens are verified with keys from jwks_uri in that metadata.
func loadAAuthJWKSSet(jwksClient jwksFetcher, stagePrefix, discoveryURL, pinJwksURI string) (jwk.Set, string, error) {
	metadata, err := jwksClient.GetMetadata(context.Background(), discoveryURL)
	if err != nil {
		return nil, "", &aauthJWKSErr{Stage: stagePrefix + ".metadata.fetch", Detail: err.Error()}
	}
	jwksURI, _ := metadata["jwks_uri"].(string)
	if jwksURI == "" {
		return nil, "", &aauthJWKSErr{Stage: stagePrefix + ".metadata.parse", Detail: "metadata is missing jwks_uri"}
	}
	if pinJwksURI != "" && pinJwksURI != jwksURI {
		return nil, "", &aauthJWKSErr{
			Stage:  stagePrefix + ".metadata.allowlist",
			Detail: fmt.Sprintf("discovered jwks_uri %q does not match configured jwks_uri %q", jwksURI, pinJwksURI),
		}
	}
	set, err := jwksClient.Get(context.Background(), jwksURI)
	if err != nil {
		return nil, jwksURI, &aauthJWKSErr{Stage: stagePrefix + ".jwks.fetch", Detail: err.Error()}
	}
	return set, jwksURI, nil
}

type jwksFetcher interface {
	Get(ctx context.Context, uri string) (jwk.Set, error)
	GetMetadata(ctx context.Context, uri string) (map[string]interface{}, error)
	Invalidate(uri string)
}

type VerifyResult struct {
	Identity    Identity
	Err         error
	Diagnostics *VerifyDiagnostics
}

type VerifyDiagnostics struct {
	Scheme string
	Stage  string
	Detail string
}

func fail(identity Identity, scheme, stage, detail string, err error) VerifyResult {
	return VerifyResult{
		Identity: identity,
		Err:      err,
		Diagnostics: &VerifyDiagnostics{
			Scheme: scheme,
			Stage:  stage,
			Detail: detail,
		},
	}
}

func Verify(rc *config.ResourceConfig, method, authority, path string, headers map[string][]string, jwksClient jwksFetcher) VerifyResult {
	// 1. Extract raw signature headers.
	if len(headers["signature"]) == 0 || len(headers["signature-input"]) == 0 || len(headers["signature-key"]) == 0 {
		return fail(Identity{}, "", "headers", "missing one or more of signature, signature-input, signature-key", ErrMissingSignature)
	}

	// 2. Parse Signature-Key.
	sigKeyStr := strings.Join(headers["signature-key"], ", ")
	parsedKey, err := sigkey.Parse(sigKeyStr)
	if err != nil {
		return fail(Identity{}, "", "signature-key.parse", err.Error(), ErrInvalidSignature)
	}

	var pubKey ed25519.PublicKey
	var identity Identity
	scheme := string(parsedKey.Scheme)

	if len(rc.AllowedSignatureKeySchemes) > 0 {
		if !stringInSlice(scheme, rc.AllowedSignatureKeySchemes) {
			return fail(identity, scheme, "config.signature_key_scheme", "signature-key scheme not allowed for this resource", ErrDisallowedSignatureKeyScheme)
		}
	}

	switch parsedKey.Scheme {
	case sigkey.SchemeHWK:
		// Non-standard pseudonymous extension: inline bare key.
		kty, _ := parsedKey.HWK["kty"].(string)
		crv, _ := parsedKey.HWK["crv"].(string)
		x, _ := parsedKey.HWK["x"].(string)

		if kty != "OKP" || crv != "Ed25519" || x == "" {
			return fail(identity, scheme, "signature-key.hwk.validate", "expected kty=OKP crv=Ed25519 and non-empty x", ErrUnsupportedAlgorithm)
		}

		xBytes, err := base64.RawURLEncoding.DecodeString(x)
		if err != nil || len(xBytes) != ed25519.PublicKeySize {
			detail := "invalid base64url or wrong Ed25519 public key length"
			if err != nil {
				detail = err.Error()
			}
			return fail(identity, scheme, "signature-key.hwk.decode", detail, ErrInvalidKey)
		}
		pub := ed25519.PublicKey(xBytes)

		jkt, jktErr := ExtractJWKThumbprint(pub)
		if jktErr != nil {
			return fail(identity, scheme, "signature-key.hwk.thumbprint", jktErr.Error(), ErrInvalidKey)
		}
		identity.JKT = jkt

		if !rc.AllowPseudonymous {
			// Level too low — return identity so a bound resource-token can be minted.
			identity.Level = LevelPseudonymous
			return fail(identity, scheme, "policy.pseudonymous", "pseudonymous identities are disabled for this resource", ErrInsufficientScope)
		}

		pubKey = pub
		identity.Level = LevelPseudonymous

	case sigkey.SchemeJWKSURI:
		if jwksClient == nil {
			return fail(identity, scheme, "jwks.fetcher", "jwks client not configured", ErrInvalidKey)
		}
		if !isAllowedDiscoveryID(parsedKey.ID) {
			return fail(identity, scheme, "signature-key.jwks_uri.validate", "id must use https unless it targets localhost for local development", ErrInvalidKey)
		}

		// Verify the discovery ID belongs to a known agent server (if configured).
		var agentServer config.AgentServer
		var matched bool
		for _, as := range rc.AgentServers {
			if as.Issuer == parsedKey.ID {
				agentServer = as
				matched = true
				break
			}
		}
		if len(rc.AgentServers) > 0 && !matched {
			return fail(identity, scheme, "signature-key.jwks_uri.allowlist", "id is not a configured agent server issuer", ErrInvalidKey)
		}
		if matched && !isAllowedDiscoveryID(agentServer.Issuer) {
			return fail(identity, scheme, "signature-key.jwks_uri.agent-server", "matched agent server issuer must use https unless it targets localhost for local development", ErrInvalidKey)
		}

		discoveryURL := strings.TrimRight(parsedKey.ID, "/") + "/.well-known/" + parsedKey.DWK
		metadata, err := jwksClient.GetMetadata(context.Background(), discoveryURL)
		if err != nil {
			return fail(identity, scheme, "jwks.metadata.fetch", err.Error(), ErrInvalidKey)
		}

		if parsedKey.KeyID == "" {
			return fail(identity, scheme, "signature-key.jwks_uri.kid", "missing kid parameter", ErrInvalidKey)
		}

		jwksURI, _ := metadata["jwks_uri"].(string)
		if jwksURI == "" {
			return fail(identity, scheme, "jwks.metadata.parse", "metadata is missing jwks_uri", ErrInvalidKey)
		}
		if agentServer.JwksURI != "" && agentServer.JwksURI != jwksURI {
			return fail(identity, scheme, "jwks.metadata.allowlist", "discovered jwks_uri does not match configured agent server jwks_uri", ErrInvalidKey)
		}

		set, err := jwksClient.Get(context.Background(), jwksURI)
		if err != nil {
			return fail(identity, scheme, "jwks.fetch", err.Error(), ErrInvalidKey)
		}

		key, ok := set.LookupKeyID(parsedKey.KeyID)
		if !ok {
			// Per Signature-Key §5.4.6, retry once after a JWKS refresh to handle rotation.
			jwksClient.Invalidate(jwksURI)
			set, err = jwksClient.Get(context.Background(), jwksURI)
			if err != nil {
				return fail(identity, scheme, "jwks.refresh", err.Error(), ErrInvalidKey)
			}
			key, ok = set.LookupKeyID(parsedKey.KeyID)
			if !ok {
				return fail(identity, scheme, "jwks.lookup", "no matching key for keyid="+parsedKey.KeyID+" after jwks refresh", ErrUnknownKey)
			}
		}

		var rawKey interface{}
		if err := key.Raw(&rawKey); err != nil {
			return fail(identity, scheme, "jwks.key.raw", err.Error(), ErrInvalidKey)
		}

		edKey, ok := rawKey.(ed25519.PublicKey)
		if !ok {
			return fail(identity, scheme, "jwks.key.type", "jwks key is not an Ed25519 public key", ErrUnsupportedAlgorithm)
		}

		pubKey = edKey
		identity.Level = LevelIdentified
		identity.AgentServer = agentServer.Issuer

		jktBytes, _ := key.Thumbprint(crypto.SHA256)
		identity.JKT = base64.RawURLEncoding.EncodeToString(jktBytes)

	case sigkey.SchemeJWT:
		if jwksClient == nil {
			return fail(identity, scheme, "jwks.fetcher", "jwks client not configured", ErrInvalidKey)
		}

		// Peek at the JWT header to get typ and iss before verifying.
		jwtHeader, jwtClaimsMap, err := parseJWTUnverified(parsedKey.JWT)
		if err != nil {
			return fail(identity, scheme, "jwt.parse", err.Error(), ErrInvalidJWT)
		}

		typ, _ := jwtHeader["typ"].(string)
		iss, _ := jwtClaimsMap["iss"].(string)
		dwk, _ := jwtClaimsMap["dwk"].(string)

		if len(rc.AllowedJWTTypes) > 0 && !stringInSlice(strings.ToLower(typ), rc.AllowedJWTTypes) {
			return fail(identity, scheme, "config.jwt_typ", "jwt typ not allowed for this resource: "+typ, ErrDisallowedJWTType)
		}

		if typ == "aa-agent+jwt" {
			// Verify the issuer is a known agent server (if configured).
			var agentServer config.AgentServer
			var matchedAS bool
			for _, as := range rc.AgentServers {
				if as.Issuer == iss {
					agentServer = as
					matchedAS = true
					break
				}
			}
			if len(rc.AgentServers) > 0 && !matchedAS {
				return fail(identity, scheme, "jwt.agent.issuer", "issuer is not a configured agent server: "+iss, ErrInvalidJWT)
			}
			if !isAllowedDiscoveryID(iss) {
				return fail(identity, scheme, "jwt.agent.issuer", "issuer must use https, or http for localhost", ErrInvalidJWT)
			}

			// All AAuth JWTs: verify using jwks_uri from issuer well-known metadata (SPEC.md).
			if dwk != "aauth-agent.json" {
				return fail(identity, scheme, "jwt.agent.dwk", "expected dwk=aauth-agent.json, got "+dwk, ErrInvalidJWT)
			}
			discoveryURL := strings.TrimRight(iss, "/") + "/.well-known/" + dwk
			var pinJwksURI string
			if matchedAS {
				pinJwksURI = agentServer.JwksURI
			}
			set, _, err := loadAAuthJWKSSet(jwksClient, "jwt.agent", discoveryURL, pinJwksURI)
			if err != nil {
				var aje *aauthJWKSErr
				if errors.As(err, &aje) {
					return fail(identity, scheme, aje.Stage, aje.Detail, ErrInvalidKey)
				}
				return fail(identity, scheme, "jwt.agent.jwks.fetch", err.Error(), ErrInvalidKey)
			}

			// Align with jwt.agent.issuer: iss is already vetted for discovery; do not
			// re-require https in Parse when http for localhost/127.0.0.1/::1/*.localhost.
			// allow_insecure_jwt_issuer relaxes the claim for other optional deployment modes.
			issOKInJWT := isAllowedDiscoveryID(iss) || rc.AllowInsecureJWTIssuer
			agentClaims, err := ParseAndVerifyAgentToken(parsedKey.JWT, set, rc.Issuer, issOKInJWT)
			if err != nil {
				return fail(identity, scheme, "jwt.agent.verify", err.Error(), err)
			}

			// The HTTP request must be signed with the key bound in cnf.jwk.
			pubKey = extractEd25519FromCnf(jwtClaimsMap)
			if pubKey == nil {
				return fail(identity, scheme, "jwt.agent.cnf", "missing or invalid cnf.jwk Ed25519 public key", ErrInvalidKey)
			}

			identity.Level = LevelIdentified
			identity.AgentServer = iss
			identity.Delegate = agentClaims.Sub
			identity.JKT = agentClaims.CnfJWK

		} else if typ == "aa-auth+jwt" {
			// Verify the issuer is a known auth server (if configured).
			var authServer config.AuthServer
			var matchedAuth bool
			for _, as := range rc.AuthServers {
				if as.Issuer == iss {
					authServer = as
					matchedAuth = true
					break
				}
			}
			if len(rc.AuthServers) > 0 && !matchedAuth {
				return fail(identity, scheme, "jwt.auth.issuer", "issuer is not a configured auth server: "+iss, ErrInvalidJWT)
			}
			if !isAllowedDiscoveryID(iss) {
				return fail(identity, scheme, "jwt.auth.issuer", "issuer must use https, or http for localhost", ErrInvalidJWT)
			}

			// jwks_uri from issuer well-known metadata (SPEC.md).
			if dwk == "" {
				return fail(identity, scheme, "jwt.auth.dwk", "missing dwk claim", ErrInvalidJWT)
			}
			discoveryURL := strings.TrimRight(iss, "/") + "/.well-known/" + dwk
			var pinAuthJwks string
			if matchedAuth {
				pinAuthJwks = authServer.JwksURI
			}
			set, _, err := loadAAuthJWKSSet(jwksClient, "jwt.auth", discoveryURL, pinAuthJwks)
			if err != nil {
				var aje *aauthJWKSErr
				if errors.As(err, &aje) {
					return fail(identity, scheme, aje.Stage, aje.Detail, ErrInvalidKey)
				}
				return fail(identity, scheme, "jwt.auth.jwks.fetch", err.Error(), ErrInvalidKey)
			}

			issOKInJWT := isAllowedDiscoveryID(iss) || rc.AllowInsecureJWTIssuer
			authClaims, err := ParseAndVerifyAuthToken(parsedKey.JWT, set, rc.Issuer, issOKInJWT)
			if err != nil {
				return fail(identity, scheme, "jwt.auth.verify", err.Error(), err)
			}

			// The HTTP request must be signed with the key bound in cnf.jwk.
			pubKey = extractEd25519FromCnf(jwtClaimsMap)
			if pubKey == nil {
				return fail(identity, scheme, "jwt.auth.cnf", "missing or invalid cnf.jwk Ed25519 public key", ErrInvalidKey)
			}

			// Verify act.sub matches cnf.jwk thumbprint (the agent's signing key identity).
			if authClaims.Act == nil || authClaims.Act.Sub != authClaims.CnfJWK {
				return fail(identity, scheme, "jwt.auth.act", "act.sub must match cnf.jwk thumbprint", ErrInvalidToken)
			}

			// Verify agent is a non-empty HTTPS URL and (if configured) matches a known agent server.
			if authClaims.Agent == "" || !strings.HasPrefix(authClaims.Agent, "https://") {
				return fail(identity, scheme, "jwt.auth.agent", "agent claim must be a non-empty https URL", ErrInvalidToken)
			}

			identity.Level = LevelAuthorized
			identity.AgentServer = authClaims.Agent
			identity.Delegate = authClaims.Sub
			identity.Scope = authClaims.Scope
			identity.Txn = authClaims.Txn
			identity.JKT = authClaims.CnfJWK

		} else {
			return fail(identity, scheme, "jwt.typ", "unsupported jwt typ="+typ, ErrUnsupportedScheme)
		}

	default:
		return fail(identity, scheme, "signature-key.scheme", "unsupported signature-key scheme", ErrUnsupportedScheme)
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

	sigRes, err := httpsig.Verify(vIn)
	if err != nil {
		if errors.Is(err, httpsig.ErrMissingSignature) {
			return fail(identity, scheme, "httpsig.verify", err.Error(), ErrMissingSignature)
		}
		if errors.Is(err, httpsig.ErrMissingSignatureKeyCoverage) || errors.Is(err, httpsig.ErrMissingCoverage) {
			return fail(identity, scheme, "httpsig.coverage", err.Error(), ErrInvalidInput)
		}
		if errors.Is(err, httpsig.ErrUnsupportedAlgorithm) {
			return fail(identity, scheme, "httpsig.algorithm", err.Error(), ErrUnsupportedAlgorithm)
		}
		return fail(identity, scheme, "httpsig.verify", err.Error(), ErrInvalidSignature)
	}
	if parsedKey.KeyID != "" && sigRes != nil && sigRes.KeyID != "" && parsedKey.KeyID != sigRes.KeyID {
		return fail(identity, scheme, "httpsig.keyid", "signature-key keyid does not match signature-input keyid", ErrInvalidSignature)
	}

	return VerifyResult{Identity: identity, Err: nil, Diagnostics: &VerifyDiagnostics{Scheme: scheme, Stage: "ok"}}
}

func stringInSlice(s string, list []string) bool {
	for _, x := range list {
		if s == x {
			return true
		}
	}
	return false
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

func isAllowedDiscoveryID(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme != "http" {
		return false
	}
	return host == "localhost" || host == "127.0.0.1" || host == "::1" || strings.HasSuffix(host, ".localhost")
}

// issAllowedInAAuthJWT enforces the spec default (https only) or, when allowInsecure is true,
// the same http host allowlist as discovery URLs (isAllowedDiscoveryID) for local demos.
func issAllowedInAAuthJWT(iss string, allowInsecure bool) bool {
	if iss == "" {
		return false
	}
	if strings.HasPrefix(iss, "https://") {
		return true
	}
	if !allowInsecure {
		return false
	}
	return isAllowedDiscoveryID(iss)
}
