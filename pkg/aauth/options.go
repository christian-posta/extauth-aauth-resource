package aauth

import (
	"crypto"
	"log/slog"
	"time"
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
}

type MintResourceTokenOptions struct {
	Issuer        string
	Aud           string
	SigningKeyKid string
	SigningKey    crypto.Signer
}
