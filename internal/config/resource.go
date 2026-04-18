package config

import (
	"crypto/ed25519"
	"time"
)

// ResourceConfig represents the configuration for a single protected resource.
type ResourceConfig struct {
	ID                            string
	Issuer                        string
	Hosts                         []string
	SigningKey                    SigningKey
	PrivateKey                    ed25519.PrivateKey // Added to keep the loaded key in memory
	SignatureWindow               time.Duration
	AdditionalSignatureComponents []string
	SupportedScopes               []string
	ScopeDescriptions             map[string]string
	AuthorizationEndpoint         string
	AllowPseudonymous             bool
	StripSignatureHeaders         bool
	AuthServers                   []AuthServer
	AgentServers                  []AgentServer
	Policy                        PolicyConfig
}

type SigningKey struct {
	Kid            string
	Alg            string
	PrivateKeyFile string
}

type AuthServer struct {
	Issuer  string
	JwksURI string
}

type AgentServer struct {
	Issuer  string
	JwksURI string
}

type PolicyConfig struct {
	Name string
}
