package aauth

import (
	pb "aauth-service/gen/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type Level string

const (
	LevelPseudonymous Level = "pseudonymous"
	LevelIdentified   Level = "identified"
	LevelAuthorized   Level = "authorized"
)

type Identity struct {
	Level       Level
	Scheme      string
	TokenType   string
	Issuer      string
	KeyID       string
	AgentServer string
	Delegate    string
	Scope       string
	// ActSub is RFC 8693 act.sub from aa-auth+jwt (the acting agent). Empty for other verification paths.
	ActSub string
	Txn    string
	JKT    string
}

func ToUpstreamHeaders(id Identity) []*pb.HeaderValueOption {
	var headers []*pb.HeaderValueOption

	add := func(k, v string) {
		if v != "" {
			headers = append(headers, &pb.HeaderValueOption{
				Header: &pb.HeaderValue{Key: k, Value: v},
				Append: &wrapperspb.BoolValue{Value: false},
			})
		}
	}

	add("x-aauth-level", string(id.Level))
	add("x-aauth-agent-server", id.AgentServer)
	add("x-aauth-delegate", id.Delegate)
	add("x-aauth-scope", id.Scope)
	add("x-aauth-txn", id.Txn)
	add("x-aauth-jkt", id.JKT)

	return headers
}

// ExtAuthzDynamicMetadata builds ext_authz dynamic metadata for downstream CEL.
func ExtAuthzDynamicMetadata(id Identity) (*structpb.Struct, error) {
	if id.Level == "" {
		return nil, nil
	}
	fields := map[string]interface{}{
		"level": string(id.Level),
	}
	if id.Scheme != "" {
		fields["scheme"] = id.Scheme
	}
	if id.TokenType != "" {
		fields["token_type"] = id.TokenType
	}
	if id.Issuer != "" {
		fields["issuer"] = id.Issuer
	}
	if id.KeyID != "" {
		fields["key_id"] = id.KeyID
	}
	if id.JKT != "" {
		fields["jkt"] = id.JKT
	}
	if id.Level == LevelAuthorized && id.AgentServer != "" {
		// Preserve the original aa-auth+jwt metadata contract.
		fields["agent"] = id.AgentServer
	}
	if id.Level == LevelIdentified && id.AgentServer != "" {
		fields["agent_server"] = id.AgentServer
	}
	if id.Scope != "" {
		fields["scope"] = id.Scope
	}
	if id.Txn != "" {
		fields["txn"] = id.Txn
	}
	if id.ActSub != "" {
		fields["act"] = map[string]interface{}{"sub": id.ActSub}
	}
	if id.Delegate != "" {
		fields["sub"] = id.Delegate
	}
	if len(fields) == 0 {
		return nil, nil
	}
	return structpb.NewStruct(fields)
}
