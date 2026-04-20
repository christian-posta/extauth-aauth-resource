package aauth

import (
	"encoding/json"
	"time"

	"google.golang.org/protobuf/types/known/wrapperspb"

	pb "policy_engine/gen/proto"
	"policy_engine/internal/config"
	"policy_engine/pkg/httpsig/structfields"
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
		{Name: "auth-server", Value: structfields.Item{Value: c.Resource.AuthorizationEndpoint}},
	}

	// resource-token is REQUIRED when we have agent identity (two-step flow: first
	// unsigned request cannot include it since there is no JKT yet; signed retries can).
	if c.IssueResourceToken && c.AgentHint != nil && c.AgentHint.AgentJKT != "" {
		claims := ResourceTokenClaims{
			Iss:      c.Resource.Issuer,
			Agent:    c.AgentHint.AgentIdentifier,
			AgentJKT: c.AgentHint.AgentJKT,
			Exp:      time.Now().Add(5 * time.Minute).Unix(),
		}

		if c.AgentHint.Scope != "" {
			claims.Scope = c.AgentHint.Scope
		}
		if len(c.Resource.AuthServers) > 0 {
			claims.Aud = c.Resource.AuthServers[0].Issuer
		} else {
			claims.Aud = c.Resource.AuthorizationEndpoint
		}

		tokenStr := "dummy.token.sig"
		if len(c.Resource.PrivateKey) > 0 {
			token, err := MintResourceToken(c.Resource, claims, c.Resource.PrivateKey)
			if err == nil {
				tokenStr = token
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
