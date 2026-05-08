package aauth

import (
	"crypto"
	"log/slog"
	"time"

	"aauth-service/pkg/aauth/headers"
)

type AgentServer struct {
	Issuer  string
	JwksURI string
}

type AuthServer struct {
	Issuer  string
	JwksURI string
}

type PersonServer struct {
	Issuer  string
	JwksURI string
}

type VerifyOptions struct {
	Issuer                        string
	AgentServers                  []AgentServer
	AuthServers                   []AuthServer
	AllowedSignatureKeySchemes    []string
	AllowedJWTTypes               []string
	AdditionalSignatureComponents []string
	SignatureWindow               time.Duration
	AllowPseudonymous             bool
	AllowInsecureJWTIssuer        bool
	Logger                        *slog.Logger
}

type ChallengeOptions struct {
	Issuer                        string
	ResourceID                    string
	AAud                          string
	AdditionalSignatureComponents []string
	AllowPseudonymous             bool
	AgentServersConfigured        bool
	AuthServersConfigured         bool
	DefaultResourceTokenScopes    []string
	SigningKeyKid                 string
	SigningKey                    crypto.Signer
	Logger                        *slog.Logger
	// Requirements is an explicit list of requirements to include in the challenge.
	// When non-empty, these drive the AAuth-Requirement and Accept-Signature headers
	// instead of the default requirement-inference logic. Existing behaviour is
	// preserved when Requirements is nil.
	Requirements []headers.Requirement
}

type MintResourceTokenOptions struct {
	Issuer        string
	Aud           string
	SigningKeyKid string
	SigningKey    crypto.Signer
}
