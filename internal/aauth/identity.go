package aauth

import (
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
	pb "aauth-service/gen/proto"
)

type Level string

const (
	LevelPseudonymous Level = "pseudonymous"
	LevelIdentified   Level = "identified"
	LevelAuthorized   Level = "authorized"
)

type Identity struct {
	Level       Level
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

// ExtAuthzDynamicMetadata builds ext_authz dynamic metadata for downstream CEL (e.g. extauthz.agent)
// when the caller presented a valid aa-auth+jwt (LevelAuthorized). Returns nil for other levels.
func ExtAuthzDynamicMetadata(id Identity) (*structpb.Struct, error) {
	if id.Level != LevelAuthorized {
		return nil, nil
	}
	fields := map[string]interface{}{}
	if id.AgentServer != "" {
		fields["agent"] = id.AgentServer
	}
	if id.Scope != "" {
		fields["scope"] = id.Scope
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
