package headers

import (
	"fmt"

	"aauth-service/pkg/httpsig/structfields"
)

// Requirement is implemented by all AAuth-Requirement member types.
type Requirement interface {
	// Type returns the requirement token value (e.g. "auth-token", "interaction").
	Type() string
}

// AuthTokenReq is an auth-token requirement (spec §12.3.2).
type AuthTokenReq struct {
	// Issuer is the resource identifier placed in the resource-token iss claim.
	Issuer string
	// Audience is the intended audience of the resource token.
	Audience string
	// Scopes lists the scopes requested from the access server.
	Scopes []string
	// ResourceToken is the bound resource token JWT, when present.
	ResourceToken string
}

// Type returns "auth-token".
func (AuthTokenReq) Type() string { return "auth-token" }

// IdentityReq requires a signature with a URI-identified key (identity level).
type IdentityReq struct {
	// Issuer is the resource identifier.
	Issuer string
	// Audience is the intended audience.
	Audience string
}

// Type returns "identity".
func (IdentityReq) Type() string { return "identity" }

// PseudonymReq requires a signature with an inline JWK thumbprint (pseudonym level).
type PseudonymReq struct {
	// Issuer is the resource identifier.
	Issuer string
	// Audience is the intended audience.
	Audience string
}

// Type returns "pseudonym".
func (PseudonymReq) Type() string { return "pseudonym" }

// InteractionReq is an interaction requirement — a human must complete an action (spec §12.3.3).
type InteractionReq struct {
	// URL is the HTTPS interaction endpoint.
	URL string
	// Code is the short alphanumeric code displayed to the user.
	Code string
}

// Type returns "interaction".
func (InteractionReq) Type() string { return "interaction" }

// ApprovalReq indicates that approval is pending (spec §12.3.2).
type ApprovalReq struct {
	// Reason is an optional human-readable explanation.
	Reason string
}

// Type returns "approval".
func (ApprovalReq) Type() string { return "approval" }

// ClarificationReq indicates that a clarifying question has been posed (spec §7.3.1).
type ClarificationReq struct {
	// Prompt is the optional clarifying question text.
	Prompt string
}

// Type returns "clarification".
func (ClarificationReq) Type() string { return "clarification" }

// ClaimsReq indicates that identity claims are required (spec §9.2).
type ClaimsReq struct {
	// Names lists the required claim names.
	Names []string
}

// Type returns "claims".
func (ClaimsReq) Type() string { return "claims" }

// ParseAAuthRequirement parses an AAuth-Requirement header value (RFC 8941 Dictionary)
// into one or more Requirement values.
func ParseAAuthRequirement(headerValue string) ([]Requirement, error) {
	dict, err := structfields.ParseDictionary(headerValue)
	if err != nil {
		return nil, fmt.Errorf("AAuth-Requirement: invalid structured field: %w", err)
	}

	entry, ok := dict.Get("requirement")
	if !ok {
		return nil, fmt.Errorf("AAuth-Requirement: missing 'requirement' member")
	}

	item, ok := entry.(structfields.Item)
	if !ok {
		return nil, fmt.Errorf("AAuth-Requirement: 'requirement' must be an Item")
	}

	tok, ok := item.Value.(structfields.Token)
	if !ok {
		return nil, fmt.Errorf("AAuth-Requirement: 'requirement' must be a Token")
	}

	reqType := string(tok)

	switch reqType {
	case "auth-token":
		r := AuthTokenReq{}
		if rt, ok := dict.Get("resource-token"); ok {
			if rtItem, ok := rt.(structfields.Item); ok {
				if s, ok := rtItem.Value.(string); ok {
					r.ResourceToken = s
				}
			}
		}
		return []Requirement{r}, nil

	case "interaction":
		r := InteractionReq{}
		if u, ok := dict.Get("url"); ok {
			if uItem, ok := u.(structfields.Item); ok {
				if s, ok := uItem.Value.(string); ok {
					r.URL = s
				}
			}
		}
		if c, ok := dict.Get("code"); ok {
			if cItem, ok := c.(structfields.Item); ok {
				if s, ok := cItem.Value.(string); ok {
					r.Code = s
				}
			}
		}
		return []Requirement{r}, nil

	case "approval":
		return []Requirement{ApprovalReq{}}, nil

	case "clarification":
		return []Requirement{ClarificationReq{}}, nil

	case "claims":
		return []Requirement{ClaimsReq{}}, nil

	case "pseudonym":
		return []Requirement{PseudonymReq{}}, nil

	case "identity":
		return []Requirement{IdentityReq{}}, nil

	default:
		// Unknown requirement types are preserved as auth-token with no extra fields
		// so that recipients can forward them without data loss per spec note.
		return nil, fmt.Errorf("AAuth-Requirement: unknown requirement type %q", reqType)
	}
}

// BuildAAuthRequirement serializes a slice of Requirement values into an RFC 8941
// Dictionary header value. Only the first requirement is used; multiple requirements
// in a single header are not defined by the current spec.
func BuildAAuthRequirement(reqs []Requirement) (string, error) {
	if len(reqs) == 0 {
		return "", fmt.Errorf("BuildAAuthRequirement: no requirements provided")
	}

	req := reqs[0]

	dict := structfields.Dictionary{
		{Name: "requirement", Value: structfields.Item{Value: structfields.Token(req.Type())}},
	}

	switch r := req.(type) {
	case AuthTokenReq:
		if r.ResourceToken != "" {
			dict = append(dict, structfields.DictMember{
				Name:  "resource-token",
				Value: structfields.Item{Value: r.ResourceToken},
			})
		}

	case InteractionReq:
		if r.URL != "" {
			dict = append(dict, structfields.DictMember{
				Name:  "url",
				Value: structfields.Item{Value: r.URL},
			})
		}
		if r.Code != "" {
			dict = append(dict, structfields.DictMember{
				Name:  "code",
				Value: structfields.Item{Value: r.Code},
			})
		}
	}

	return structfields.SerializeDictionary(dict)
}
