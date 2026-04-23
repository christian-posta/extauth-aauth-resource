package config

import (
	"fmt"
	"strings"
)

// Known Signature-Key scheme names (RFC 9421 / AAuth).
const (
	SchemeHWK     = "hwk"
	SchemeJWKSURI = "jwks_uri"
	SchemeJWT     = "jwt"
)

// JWT typ values accepted in the jwt Signature-Key scheme.
const (
	JWTTypeAgent = "aa-agent+jwt"
	JWTTypeAuth  = "aa-auth+jwt"
)

var allowedSchemes = map[string]struct{}{
	SchemeHWK:     {},
	SchemeJWKSURI: {},
	SchemeJWT:     {},
}

var allowedJWTTyp = map[string]struct{}{
	JWTTypeAgent: {},
	JWTTypeAuth:  {},
}

// NormalizeAndDedupeTokens trims, lowercases, and dedupes entries (order preserved).
func NormalizeAndDedupeTokens(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{})
	out := make([]string, 0, len(in))
	for _, s := range in {
		t := strings.ToLower(strings.TrimSpace(s))
		if t == "" {
			continue
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// ValidateResource checks resource fields after YAML mapping and ToDomain.
func ValidateResource(rc *ResourceConfig) error {
	if err := validateSignatureKeySchemes(rc); err != nil {
		return err
	}
	return validateJWTTypes(rc)
}

func validateSignatureKeySchemes(rc *ResourceConfig) error {
	for _, s := range rc.AllowedSignatureKeySchemes {
		if _, ok := allowedSchemes[s]; !ok {
			return fmt.Errorf("resource %q: unknown allowed_signature_key_schemes entry %q (want hwk, jwks_uri, or jwt)", rc.ID, s)
		}
	}
	if len(rc.AllowedSignatureKeySchemes) == 0 {
		return nil
	}
	hasHWK := false
	for _, s := range rc.AllowedSignatureKeySchemes {
		if s == SchemeHWK {
			hasHWK = true
			break
		}
	}
	if hasHWK && !rc.AllowPseudonymous {
		return fmt.Errorf("resource %q: allowed_signature_key_schemes includes hwk but allow_pseudonymous is false", rc.ID)
	}
	return nil
}

func validateJWTTypes(rc *ResourceConfig) error {
	for _, t := range rc.AllowedJWTTypes {
		if _, ok := allowedJWTTyp[t]; !ok {
			return fmt.Errorf("resource %q: unknown allowed_jwt_types entry %q (want %q or %q)", rc.ID, t, JWTTypeAgent, JWTTypeAuth)
		}
	}
	if len(rc.AllowedJWTTypes) == 0 {
		return nil
	}
	// Explicit jwt typ list only makes sense when jwt can appear on the wire.
	if len(rc.AllowedSignatureKeySchemes) > 0 {
		jwtOK := false
		for _, s := range rc.AllowedSignatureKeySchemes {
			if s == SchemeJWT {
				jwtOK = true
				break
			}
		}
		if !jwtOK {
			return fmt.Errorf("resource %q: allowed_jwt_types is set but allowed_signature_key_schemes does not include jwt", rc.ID)
		}
	}
	return nil
}
