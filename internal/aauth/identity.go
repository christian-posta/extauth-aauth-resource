package aauth

import (
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
	Txn         string
	JKT         string
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
