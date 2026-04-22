package sigkey

import (
	"errors"
	"fmt"

	"aauth-service/pkg/httpsig/structfields"
)

var (
	ErrInvalidHeader     = errors.New("invalid signature-key header")
	ErrUnsupportedScheme = errors.New("unsupported signature-key scheme")
	ErrMissingScheme     = errors.New("missing scheme in signature-key")
)

// Parse extracts the signature key parameters from a Signature-Key header value.
//
// The header follows the HTTP Signature Keys specification. The format is an
// RFC 8941 Dictionary with exactly one entry whose key is an arbitrary label
// (typically "sig") and whose value is an Item. The Item's bare value is a
// Token that names the scheme (e.g. "jwt", "jwks_uri", "hwk"). Scheme-specific
// parameters are carried in the Item's parameters.
//
// Examples (per spec):
//
//	Signature-Key: sig=jwt; jwt="eyJhbGc..."
//	Signature-Key: sig=jwks_uri;id="https://client.example";dwk="aauth-agent.json";kid="key-1"
//
// The "hwk" scheme is a non-standard extension for pseudonymous inline keys:
//
//	Signature-Key: sig=hwk; kty="OKP"; crv="Ed25519"; x="..."
func Parse(headerValue string) (Parsed, error) {
	dict, err := structfields.ParseDictionary(headerValue)
	if err != nil {
		return Parsed{}, fmt.Errorf("%w: %v", ErrInvalidHeader, err)
	}

	if len(dict) != 1 {
		return Parsed{}, fmt.Errorf("%w: expected exactly one entry, got %d", ErrInvalidHeader, len(dict))
	}

	entry := dict[0]
	item, ok := entry.Value.(structfields.Item)
	if !ok {
		return Parsed{}, fmt.Errorf("%w: entry must be an Item", ErrInvalidHeader)
	}

	// The scheme is the Token value of the Item, not a parameter.
	scheme, ok := item.Value.(structfields.Token)
	if !ok {
		return Parsed{}, fmt.Errorf("%w: scheme must be a Token (bare identifier)", ErrInvalidHeader)
	}

	params := item.Params

	parsed := Parsed{
		Scheme: Scheme(scheme),
	}

	if kidParam, ok := params.Get("kid"); ok {
		if kidStr, ok := kidParam.(string); ok {
			parsed.KeyID = kidStr
		}
	}

	switch parsed.Scheme {
	case SchemeHWK:
		// Non-standard pseudonymous extension. All params (except kid) are JWK fields.
		parsed.HWK = make(map[string]interface{})
		for _, p := range params {
			if p.Name != "kid" {
				parsed.HWK[p.Name] = p.Value
			}
		}

	case SchemeJWT:
		jwtParam, ok := params.Get("jwt")
		if !ok {
			return Parsed{}, fmt.Errorf("%w: missing 'jwt' parameter for jwt scheme", ErrInvalidHeader)
		}
		jwtStr, ok := jwtParam.(string)
		if !ok {
			return Parsed{}, fmt.Errorf("%w: 'jwt' parameter must be a string", ErrInvalidHeader)
		}
		parsed.JWT = jwtStr

	case SchemeJWKSURI:
		idParam, ok := params.Get("id")
		if !ok {
			return Parsed{}, fmt.Errorf("%w: missing 'id' parameter for jwks_uri scheme", ErrInvalidHeader)
		}
		idStr, ok := idParam.(string)
		if !ok {
			return Parsed{}, fmt.Errorf("%w: 'id' parameter must be a string", ErrInvalidHeader)
		}
		dwkParam, ok := params.Get("dwk")
		if !ok {
			return Parsed{}, fmt.Errorf("%w: missing 'dwk' parameter for jwks_uri scheme", ErrInvalidHeader)
		}
		dwkStr, ok := dwkParam.(string)
		if !ok {
			return Parsed{}, fmt.Errorf("%w: 'dwk' parameter must be a string", ErrInvalidHeader)
		}
		if parsed.KeyID == "" {
			return Parsed{}, fmt.Errorf("%w: missing 'kid' parameter for jwks_uri scheme", ErrInvalidHeader)
		}
		parsed.ID = idStr
		parsed.DWK = dwkStr

	case SchemeX509:
		return Parsed{}, ErrUnsupportedScheme

	default:
		return Parsed{}, fmt.Errorf("%w: %s", ErrUnsupportedScheme, string(scheme))
	}

	return parsed, nil
}
