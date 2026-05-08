package aauth

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"aauth-service/pkg/aauth/headers"
	"aauth-service/pkg/httpsig/structfields"
)

// AgentHint carries enough information about the presenting agent to allow the
// resource to mint a bound resource-token even when the request itself fails.
type AgentHint struct {
	// AgentIdentifier is the agent's stable identifier (sub from the agent token,
	// e.g. "aauth:alice@agents.example.com"). Used as the "agent" claim in
	// resource tokens per the AAuth spec.
	AgentIdentifier string
	// AgentJKT is the RFC 7638 thumbprint of the agent's signing key.
	AgentJKT string
	// Scope is optional scope context from a failed auth token request.
	Scope string
}

// ChallengeResponse is the transport-agnostic outcome of building a 401 challenge.
type ChallengeResponse struct {
	Status           int
	Headers          http.Header
	Body             []byte
	ResourceTokenJTI string
}

type Challenge struct {
	Opts               ChallengeOptions
	Err                error
	AgentHint          *AgentHint
	IssueResourceToken bool
}

func NewChallenge(opts ChallengeOptions, err error, hint *AgentHint, issueToken bool) *Challenge {
	return &Challenge{
		Opts:               opts,
		Err:                err,
		AgentHint:          hint,
		IssueResourceToken: issueToken,
	}
}

func (c *Challenge) logger() *slog.Logger {
	if c.Opts.Logger != nil {
		return c.Opts.Logger
	}
	return slog.Default()
}

func (c *Challenge) Build() ChallengeResponse {
	// Determine error code for the JSON body.
	errCode := "invalid_request"
	if c.Err != nil {
		errCode = c.Err.Error()
	}

	bodyBytes, _ := json.Marshal(map[string]string{
		"error": errCode,
	})

	// Build AAuth-Requirement header using RFC 8941 Structured Fields.
	reqDict := structfields.Dictionary{
		{Name: "requirement", Value: structfields.Item{Value: structfields.Token("auth-token")}},
	}

	resp := ChallengeResponse{
		Status:  http.StatusUnauthorized,
		Headers: http.Header{},
	}

	// resource-token is REQUIRED when we have agent identity (two-step flow: first
	// unsigned request cannot include it since there is no JKT yet; signed retries can).
	if c.IssueResourceToken && c.AgentHint != nil && c.AgentHint.AgentJKT != "" {
		scope := strings.Join(c.Opts.DefaultResourceTokenScopes, " ")
		if scope == "" {
			scope = c.AgentHint.Scope
		}

		claims := ResourceTokenClaims{
			Iss:      c.Opts.Issuer,
			Agent:    c.AgentHint.AgentIdentifier,
			AgentJKT: c.AgentHint.AgentJKT,
			Exp:      time.Now().Add(5 * time.Minute).Unix(),
		}

		if scope != "" {
			claims.Scope = scope
		}
		claims.Aud = c.Opts.AAud

		if c.Opts.SigningKey == nil || c.Opts.SigningKeyKid == "" {
			c.logger().Warn("resource-token requested but signing key is unavailable",
				slog.String("resource", c.Opts.ResourceID))
		} else {
			mintOpts := MintResourceTokenOptions{
				Issuer:        c.Opts.Issuer,
				Aud:           claims.Aud,
				SigningKeyKid: c.Opts.SigningKeyKid,
				SigningKey:    c.Opts.SigningKey,
			}
			token, err := MintResourceToken(mintOpts, claims)
			if err != nil {
				c.logger().Error("failed to mint resource token",
					slog.String("resource", c.Opts.ResourceID),
					slog.Any("error", err))
			} else {
				_, parsedClaims, parseErr := parseJWTUnverified(token)
				if parseErr == nil {
					if jti, ok := parsedClaims["jti"].(string); ok {
						resp.ResourceTokenJTI = jti
					}
				}
				// resource-token must be a String (quoted) in the SF dictionary — JWTs contain
				// dots which are valid Token chars, but the spec explicitly calls for a String type.
				reqDict = append(reqDict, structfields.DictMember{
					Name:  "resource-token",
					Value: structfields.Item{Value: token},
				})
			}
		}
	}

	reqHeaderStr, _ := structfields.SerializeDictionary(reqDict)

	// Use literal keys (no canonicalization) so consumers see exactly the
	// names the AAuth spec uses on the wire.
	resp.Headers["WWW-Authenticate"] = []string{"AAuth"}
	resp.Headers["Content-Type"] = []string{"application/json"}

	if len(c.Opts.Requirements) > 0 {
		// Explicit requirements drive header generation.
		c.buildRequirementHeaders(resp.Headers)
	} else {
		resp.Headers["AAuth-Requirement"] = []string{reqHeaderStr}
		if sigErrHeader, ok := c.signatureErrorHeader(); ok {
			resp.Headers["Signature-Error"] = []string{sigErrHeader}
		}
		if acceptSigHeader, ok := c.acceptSignatureHeader(); ok {
			resp.Headers["Accept-Signature"] = []string{acceptSigHeader}
		}
	}

	resp.Body = bodyBytes
	return resp
}

func (c *Challenge) signatureErrorHeader() (string, bool) {
	if c.Err == nil {
		return "", false
	}

	dict := structfields.Dictionary{}

	switch c.Err {
	case ErrMissingSignature, ErrInvalidSignature:
		dict = append(dict, structfields.DictMember{
			Name:  "error",
			Value: structfields.Item{Value: structfields.Token("invalid_signature")},
		})
	case ErrInvalidInput:
		items := []structfields.Item{
			{Value: "@method"},
			{Value: "@authority"},
			{Value: "@path"},
			{Value: "signature-key"},
		}
		for _, comp := range c.Opts.AdditionalSignatureComponents {
			items = append(items, structfields.Item{Value: comp})
		}
		dict = append(dict,
			structfields.DictMember{
				Name:  "error",
				Value: structfields.Item{Value: structfields.Token("invalid_input")},
			},
			structfields.DictMember{
				Name:  "required_input",
				Value: structfields.InnerList{Items: items},
			},
		)
	case ErrUnsupportedAlgorithm:
		dict = append(dict,
			structfields.DictMember{
				Name:  "error",
				Value: structfields.Item{Value: structfields.Token("unsupported_algorithm")},
			},
			structfields.DictMember{
				Name: "supported_algorithms",
				Value: structfields.InnerList{Items: []structfields.Item{
					{Value: "ed25519"},
				}},
			},
		)
	case ErrInvalidKey:
		dict = append(dict, structfields.DictMember{
			Name:  "error",
			Value: structfields.Item{Value: structfields.Token("invalid_key")},
		})
	case ErrUnknownKey:
		dict = append(dict, structfields.DictMember{
			Name:  "error",
			Value: structfields.Item{Value: structfields.Token("unknown_key")},
		})
	case ErrInvalidJWT:
		dict = append(dict, structfields.DictMember{
			Name:  "error",
			Value: structfields.Item{Value: structfields.Token("invalid_jwt")},
		})
	case ErrExpiredJWT:
		dict = append(dict, structfields.DictMember{
			Name:  "error",
			Value: structfields.Item{Value: structfields.Token("expired_jwt")},
		})
	case ErrUnsupportedScheme:
		dict = append(dict, structfields.DictMember{
			Name:  "error",
			Value: structfields.Item{Value: structfields.Token("invalid_key")},
		})
	case ErrDisallowedSignatureKeyScheme:
		dict = append(dict, structfields.DictMember{
			Name:  "error",
			Value: structfields.Item{Value: structfields.Token("invalid_key")},
		})
	case ErrDisallowedJWTType:
		dict = append(dict, structfields.DictMember{
			Name:  "error",
			Value: structfields.Item{Value: structfields.Token("invalid_jwt")},
		})
	default:
		return "", false
	}

	s, err := structfields.SerializeDictionary(dict)
	if err != nil {
		return "", false
	}
	return s, true
}

func (c *Challenge) acceptSignatureHeader() (string, bool) {
	if c.Err == nil {
		return "", false
	}
	if _, ok := c.signatureErrorHeader(); !ok {
		return "", false
	}

	baseItems := []structfields.Item{
		{Value: "@method"},
		{Value: "@authority"},
		{Value: "@path"},
	}
	for _, comp := range c.Opts.AdditionalSignatureComponents {
		if comp != "signature-key" {
			baseItems = append(baseItems, structfields.Item{Value: comp})
		}
	}

	dict := structfields.Dictionary{}
	if c.Opts.AllowPseudonymous {
		dict = append(dict, structfields.DictMember{
			Name: "sig1",
			Value: structfields.InnerList{
				Items: baseItems,
				Params: structfields.Params{
					{Name: "sigkey", Value: structfields.Token("jkt")},
				},
			},
		})
	}
	if c.Opts.AgentServersConfigured || c.Opts.AuthServersConfigured {
		dict = append(dict, structfields.DictMember{
			Name: "sig2",
			Value: structfields.InnerList{
				Items: baseItems,
				Params: structfields.Params{
					{Name: "sigkey", Value: structfields.Token("uri")},
				},
			},
		})
	}

	if len(dict) == 0 {
		return "", false
	}

	s, err := structfields.SerializeDictionary(dict)
	if err != nil {
		return "", false
	}
	return s, true
}

// buildRequirementHeaders sets AAuth-Requirement and/or Accept-Signature response
// headers based on the explicit c.Opts.Requirements slice.
//
//   - AuthTokenReq / InteractionReq / ApprovalReq / ClarificationReq / ClaimsReq
//     → AAuth-Requirement header (RFC 8941 Dictionary)
//   - PseudonymReq  → Accept-Signature with sigkey=jkt
//   - IdentityReq   → Accept-Signature with sigkey=uri
func (c *Challenge) buildRequirementHeaders(h http.Header) {
	var aAuthReqs []headers.Requirement
	var acceptSigAs *headers.AcceptSignature

	baseComponents := []string{"@method", "@authority", "@path"}
	for _, comp := range c.Opts.AdditionalSignatureComponents {
		if comp != "signature-key" {
			baseComponents = append(baseComponents, comp)
		}
	}

	for _, req := range c.Opts.Requirements {
		switch req.(type) {
		case headers.PseudonymReq:
			if acceptSigAs == nil {
				acceptSigAs = &headers.AcceptSignature{Components: baseComponents}
			}
			acceptSigAs.KeyTypes = append(acceptSigAs.KeyTypes, "jkt")

		case headers.IdentityReq:
			if acceptSigAs == nil {
				acceptSigAs = &headers.AcceptSignature{Components: baseComponents}
			}
			acceptSigAs.KeyTypes = append(acceptSigAs.KeyTypes, "uri")

		default:
			aAuthReqs = append(aAuthReqs, req)
		}
	}

	if len(aAuthReqs) > 0 {
		if s, err := headers.BuildAAuthRequirement(aAuthReqs); err == nil {
			h["AAuth-Requirement"] = []string{s}
		}
	}

	if acceptSigAs != nil {
		if s, err := headers.BuildAcceptSignature(acceptSigAs); err == nil {
			h["Accept-Signature"] = []string{s}
		}
	}
}
