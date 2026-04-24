package aauth

import (
	"encoding/json"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/wrapperspb"

	pb "aauth-service/gen/proto"
	"aauth-service/internal/config"
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

type Challenge struct {
	Resource           *config.ResourceConfig
	Err                error
	AgentHint          *AgentHint
	IssueResourceToken bool
	ResourceTokenJTI   string
}

func NewChallenge(rc *config.ResourceConfig, err error, hint *AgentHint, issueToken bool) *Challenge {
	return &Challenge{
		Resource:           rc,
		Err:                err,
		AgentHint:          hint,
		IssueResourceToken: issueToken,
	}
}

func (c *Challenge) Response() *pb.CheckResponse {
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

	// resource-token is REQUIRED when we have agent identity (two-step flow: first
	// unsigned request cannot include it since there is no JKT yet; signed retries can).
	if c.IssueResourceToken && c.AgentHint != nil && c.AgentHint.AgentJKT != "" {
		scope := strings.Join(c.Resource.DefaultResourceTokenScopes, " ")
		if scope == "" {
			scope = c.AgentHint.Scope
		}

		claims := ResourceTokenClaims{
			Iss:      c.Resource.Issuer,
			Agent:    c.AgentHint.AgentIdentifier,
			AgentJKT: c.AgentHint.AgentJKT,
			Exp:      time.Now().Add(5 * time.Minute).Unix(),
		}

		if scope != "" {
			claims.Scope = scope
		}
		claims.Aud = ResolveResourceTokenAud(c.Resource)

		tokenStr := "dummy.token.sig"
		c.ResourceTokenJTI = claims.Jti
		if len(c.Resource.PrivateKey) > 0 {
			token, err := MintResourceToken(c.Resource, claims, c.Resource.PrivateKey)
			if err == nil {
				tokenStr = token
				_, parsedClaims, parseErr := parseJWTUnverified(token)
				if parseErr == nil {
					if jti, ok := parsedClaims["jti"].(string); ok {
						c.ResourceTokenJTI = jti
					}
				}
			}
		}

		// resource-token must be a String (quoted) in the SF dictionary — JWTs contain
		// dots which are valid Token chars, but the spec explicitly calls for a String type.
		reqDict = append(reqDict, structfields.DictMember{
			Name:  "resource-token",
			Value: structfields.Item{Value: tokenStr},
		})
	}

	reqHeaderStr, _ := structfields.SerializeDictionary(reqDict)

	headers := []*pb.HeaderValueOption{
		{
			Header: &pb.HeaderValue{Key: "AAuth-Requirement", Value: reqHeaderStr},
			Append: &wrapperspb.BoolValue{Value: false},
		},
		{
			Header: &pb.HeaderValue{Key: "WWW-Authenticate", Value: "AAuth"},
			Append: &wrapperspb.BoolValue{Value: false},
		},
		{
			Header: &pb.HeaderValue{Key: "Content-Type", Value: "application/json"},
			Append: &wrapperspb.BoolValue{Value: false},
		},
	}

	if sigErrHeader, ok := c.signatureErrorHeader(); ok {
		headers = append(headers, &pb.HeaderValueOption{
			Header: &pb.HeaderValue{Key: "Signature-Error", Value: sigErrHeader},
			Append: &wrapperspb.BoolValue{Value: false},
		})
	}
	if acceptSigHeader, ok := c.acceptSignatureHeader(); ok {
		headers = append(headers, &pb.HeaderValueOption{
			Header: &pb.HeaderValue{Key: "Accept-Signature", Value: acceptSigHeader},
			Append: &wrapperspb.BoolValue{Value: false},
		})
	}

	return &pb.CheckResponse{
		Status: &pb.Status{Code: 16}, // UNAUTHENTICATED
		HttpResponse: &pb.CheckResponse_DeniedResponse{
			DeniedResponse: &pb.DeniedHttpResponse{
				Status:  &pb.HttpStatus{Code: pb.StatusCode_Unauthorized},
				Headers: headers,
				Body:    string(bodyBytes),
			},
		},
	}
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
		for _, comp := range c.Resource.AdditionalSignatureComponents {
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
	for _, comp := range c.Resource.AdditionalSignatureComponents {
		if comp != "signature-key" {
			baseItems = append(baseItems, structfields.Item{Value: comp})
		}
	}

	dict := structfields.Dictionary{}
	if c.Resource.AllowPseudonymous {
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
	if len(c.Resource.AgentServers) > 0 || len(c.Resource.AuthServers) > 0 {
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
