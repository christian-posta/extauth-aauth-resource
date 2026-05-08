package headers

import (
	"fmt"

	"aauth-service/pkg/httpsig/structfields"
)

// Error code constants for the Signature-Error header per draft-hardt-httpbis-signature-key.
const (
	ErrCodeInvalidRequest       = "invalid_request"
	ErrCodeInvalidSignature     = "invalid_signature"
	ErrCodeInvalidInput         = "invalid_input"
	ErrCodeUnsupportedAlgorithm = "unsupported_algorithm"
	ErrCodeInvalidKey           = "invalid_key"
	ErrCodeUnknownKey           = "unknown_key"
	ErrCodeInvalidJWT           = "invalid_jwt"
	ErrCodeExpiredJWT           = "expired_jwt"
)

// SignatureError represents the parsed value of a Signature-Error response header.
type SignatureError struct {
	// Code is one of the ErrCode* constants.
	Code string
	// Description is an optional human-readable explanation (from "description" member).
	Description string
	// Extra holds any unrecognised members for forward-compatibility.
	Extra map[string]string
}

// ParseSignatureError parses a Signature-Error header value (RFC 8941 Dictionary).
func ParseSignatureError(headerValue string) (*SignatureError, error) {
	dict, err := structfields.ParseDictionary(headerValue)
	if err != nil {
		return nil, fmt.Errorf("Signature-Error: invalid structured field: %w", err)
	}

	se := &SignatureError{Extra: map[string]string{}}

	for _, m := range dict {
		item, ok := m.Value.(structfields.Item)
		if !ok {
			continue
		}
		var strVal string
		switch v := item.Value.(type) {
		case structfields.Token:
			strVal = string(v)
		case string:
			strVal = v
		}

		switch m.Name {
		case "error":
			se.Code = strVal
		case "description":
			se.Description = strVal
		default:
			if strVal != "" {
				se.Extra[m.Name] = strVal
			}
		}
	}

	if se.Code == "" {
		return nil, fmt.Errorf("Signature-Error: missing 'error' member")
	}

	return se, nil
}

// BuildSignatureError serializes a SignatureError into an RFC 8941 Dictionary
// header value.
func BuildSignatureError(se *SignatureError) (string, error) {
	if se == nil {
		return "", fmt.Errorf("BuildSignatureError: nil SignatureError")
	}
	if se.Code == "" {
		return "", fmt.Errorf("BuildSignatureError: Code must not be empty")
	}

	dict := structfields.Dictionary{
		{Name: "error", Value: structfields.Item{Value: structfields.Token(se.Code)}},
	}

	if se.Description != "" {
		dict = append(dict, structfields.DictMember{
			Name:  "description",
			Value: structfields.Item{Value: se.Description},
		})
	}

	for k, v := range se.Extra {
		dict = append(dict, structfields.DictMember{
			Name:  k,
			Value: structfields.Item{Value: v},
		})
	}

	return structfields.SerializeDictionary(dict)
}
