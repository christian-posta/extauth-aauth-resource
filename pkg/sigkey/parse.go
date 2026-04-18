package sigkey

import (
	"errors"
	"fmt"

	"policy_engine/pkg/httpsig/structfields"
)

var (
	ErrInvalidHeader     = errors.New("invalid signature-key header")
	ErrUnsupportedScheme = errors.New("unsupported signature-key scheme")
	ErrMissingScheme     = errors.New("missing scheme in signature-key")
)

// Parse extracts the signature key parameters from an RFC 8941 Dictionary header.
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

	params := item.Params
	schemeParam, ok := params.Get("scheme")
	if !ok {
		return Parsed{}, ErrMissingScheme
	}

	schemeStr, ok := schemeParam.(string)
	if !ok {
		return Parsed{}, fmt.Errorf("%w: scheme must be a string", ErrInvalidHeader)
	}

	parsed := Parsed{
		Scheme: Scheme(schemeStr),
	}

	if keyidParam, ok := params.Get("keyid"); ok {
		if kidStr, ok := keyidParam.(string); ok {
			parsed.KeyID = kidStr
		}
	}

	switch parsed.Scheme {
	case SchemeHWK:
		parsed.HWK = make(map[string]interface{})
		for _, p := range params {
			if p.Name != "scheme" && p.Name != "keyid" {
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
		uriParam, ok := params.Get("uri")
		if !ok {
			return Parsed{}, fmt.Errorf("%w: missing 'uri' parameter for jwks_uri scheme", ErrInvalidHeader)
		}
		uriStr, ok := uriParam.(string)
		if !ok {
			return Parsed{}, fmt.Errorf("%w: 'uri' parameter must be a string", ErrInvalidHeader)
		}
		parsed.JWKSURI = uriStr
	case SchemeX509:
		return Parsed{}, ErrUnsupportedScheme
	default:
		return Parsed{}, fmt.Errorf("%w: %s", ErrUnsupportedScheme, schemeStr)
	}

	return parsed, nil
}
