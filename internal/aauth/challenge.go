package aauth

import (
	"encoding/json"

	"google.golang.org/protobuf/types/known/wrapperspb"

	pb "policy_engine/gen/proto"
	"policy_engine/internal/config"
	"policy_engine/pkg/httpsig/structfields"
)

type AgentHint struct {
	Agent    string
	AgentJKT string
	Scope    string
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
	// 1. Determine error code for the JSON body
	errCode := "invalid_request"
	if c.Err != nil {
		errCode = c.Err.Error()
	}

	bodyBytes, _ := json.Marshal(map[string]string{
		"error": errCode,
	})

	// 2. Build AAuth-Requirement header using structfields
	reqDict := structfields.Dictionary{
		{Name: "requirement", Value: structfields.Item{Value: structfields.Token("auth-token")}},
		{Name: "auth-server", Value: structfields.Item{Value: c.Resource.AuthorizationEndpoint}},
	}

	if c.IssueResourceToken && c.AgentHint != nil && c.AgentHint.AgentJKT != "" {
		// Generate resource token
		claims := ResourceTokenClaims{
			Iss:      c.Resource.Issuer,
			AgentJKT: c.AgentHint.AgentJKT,
			Exp:      0,           // Let MintResourceToken or caller handle real expiration
			Jti:      "TODO-UUID", // We should add a real UUID generator
		}

		// Optional fields
		if c.AgentHint.Agent != "" {
			claims.Agent = c.AgentHint.Agent
		}
		if c.AgentHint.Scope != "" {
			claims.Scope = c.AgentHint.Scope
		}
		if len(c.Resource.AuthServers) > 0 {
			claims.Aud = c.Resource.AuthServers[0].Issuer
		} else {
			claims.Aud = c.Resource.AuthorizationEndpoint // Fallback
		}

		// Currently we lack the private key here in NewChallenge because the config
		// only has paths. In a real app we'd load keys into the ResourceConfig or Registry.
		// For the sake of the challenge generation struct, we will just use a dummy token string
		// here for now until we load the private key into memory in the config layer.
		tokenStr := "dummy.token.sig"
		if len(c.Resource.PrivateKey) > 0 {
			token, err := MintResourceToken(c.Resource, claims, c.Resource.PrivateKey)
			if err == nil {
				tokenStr = token
			}
		}

		reqDict = append(reqDict, structfields.DictMember{
			Name:  "resource-token",
			Value: structfields.Item{Value: structfields.Token(tokenStr)},
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
