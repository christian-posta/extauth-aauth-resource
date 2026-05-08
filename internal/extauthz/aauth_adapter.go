package extauthz

import (
	"crypto"
	"net/http"

	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	pb "aauth-service/gen/proto"
	"aauth-service/pkg/aauth"
	"aauth-service/internal/config"
)

// BuildVerifyOptions translates a service-level resource config into the
// transport-agnostic VerifyOptions consumed by the aauth library.
func BuildVerifyOptions(rc *config.ResourceConfig) aauth.VerifyOptions {
	agents := make([]aauth.AgentServer, len(rc.AgentServers))
	for i, a := range rc.AgentServers {
		agents[i] = aauth.AgentServer{Issuer: a.Issuer, JwksURI: a.JwksURI}
	}
	auths := make([]aauth.AuthServer, len(rc.AuthServers))
	for i, a := range rc.AuthServers {
		auths[i] = aauth.AuthServer{Issuer: a.Issuer, JwksURI: a.JwksURI}
	}
	return aauth.VerifyOptions{
		Issuer:                        rc.Issuer,
		AgentServers:                  agents,
		AuthServers:                   auths,
		AllowedSignatureKeySchemes:    rc.AllowedSignatureKeySchemes,
		AllowedJWTTypes:               rc.AllowedJWTTypes,
		AdditionalSignatureComponents: rc.AdditionalSignatureComponents,
		SignatureWindow:               rc.SignatureWindow,
		AllowPseudonymous:             rc.AllowPseudonymous,
		AllowInsecureJWTIssuer:        rc.AllowInsecureJWTIssuer,
	}
}

// BuildChallengeOptions builds the protocol-level challenge options needed to
// produce a 401 response.
func BuildChallengeOptions(rc *config.ResourceConfig) aauth.ChallengeOptions {
	var signer crypto.Signer
	if len(rc.PrivateKey) > 0 {
		signer = rc.PrivateKey
	}
	return aauth.ChallengeOptions{
		Issuer:                        rc.Issuer,
		ResourceID:                    rc.ID,
		AAud:                          ResolveResourceTokenAud(rc),
		AdditionalSignatureComponents: rc.AdditionalSignatureComponents,
		AllowPseudonymous:             rc.AllowPseudonymous,
		AgentServersConfigured:        len(rc.AgentServers) > 0,
		AuthServersConfigured:         len(rc.AuthServers) > 0,
		DefaultResourceTokenScopes:    rc.DefaultResourceTokenScopes,
		SigningKeyKid:                 rc.SigningKey.Kid,
		SigningKey:                    signer,
	}
}

// BuildMintOptions wires service config into the protocol-level mint options.
func BuildMintOptions(rc *config.ResourceConfig, aud string) aauth.MintResourceTokenOptions {
	var signer crypto.Signer
	if len(rc.PrivateKey) > 0 {
		signer = rc.PrivateKey
	}
	return aauth.MintResourceTokenOptions{
		Issuer:        rc.Issuer,
		Aud:           aud,
		SigningKeyKid: rc.SigningKey.Kid,
		SigningKey:    signer,
	}
}

// IdentityHeadersToProto converts the library's http.Header output into the
// proto HeaderValueOption slice needed for an OkHttpResponse.
func IdentityHeadersToProto(h http.Header) []*pb.HeaderValueOption {
	if len(h) == 0 {
		return nil
	}
	out := make([]*pb.HeaderValueOption, 0, len(h))
	for k, vs := range h {
		for _, v := range vs {
			out = append(out, &pb.HeaderValueOption{
				Header: &pb.HeaderValue{Key: k, Value: v},
				Append: &wrapperspb.BoolValue{Value: false},
			})
		}
	}
	return out
}

// IdentityMetadataToStruct turns a plain identity metadata map into the structpb
// representation Envoy expects on CheckResponse.dynamic_metadata.
func IdentityMetadataToStruct(m map[string]any) (*structpb.Struct, error) {
	if len(m) == 0 {
		return nil, nil
	}
	return structpb.NewStruct(m)
}

// ChallengeToCheckResponse maps a transport-agnostic challenge into the proto
// CheckResponse used over gRPC.
func ChallengeToCheckResponse(cr aauth.ChallengeResponse) *pb.CheckResponse {
	headers := make([]*pb.HeaderValueOption, 0, len(cr.Headers))
	for k, vs := range cr.Headers {
		for _, v := range vs {
			headers = append(headers, &pb.HeaderValueOption{
				Header: &pb.HeaderValue{Key: k, Value: v},
				Append: &wrapperspb.BoolValue{Value: false},
			})
		}
	}

	httpStatus := pb.StatusCode(cr.Status)
	if httpStatus == 0 {
		httpStatus = pb.StatusCode_Unauthorized
	}

	return &pb.CheckResponse{
		Status: &pb.Status{Code: 16}, // UNAUTHENTICATED
		HttpResponse: &pb.CheckResponse_DeniedResponse{
			DeniedResponse: &pb.DeniedHttpResponse{
				Status:  &pb.HttpStatus{Code: httpStatus},
				Headers: headers,
				Body:    string(cr.Body),
			},
		},
	}
}

// ResolveResourceTokenAud returns the configured audience for resource tokens.
// Mode 3 pins this to the configured Person Server issuer.
func ResolveResourceTokenAud(rc *config.ResourceConfig) string {
	if rc == nil {
		return ""
	}
	if rc.PersonServer.Issuer != "" {
		return rc.PersonServer.Issuer
	}
	return ""
}
