package config

import (
	"crypto/ed25519"
	"time"
)

// ResourceConfig represents the configuration for a single protected resource.
type ResourceConfig struct {
	ID                            string
	Issuer                        string
	ClientName                    string
	LogoURI                       string
	LogoDarkURI                   string
	LoginEndpoint                 string
	Hosts                         []string
	SigningKey                    SigningKey
	PrivateKey                    ed25519.PrivateKey // Added to keep the loaded key in memory
	SignatureWindow               time.Duration
	AdditionalSignatureComponents []string
	SupportedScopes               []string
	ScopeDescriptions             map[string]string
	DefaultResourceTokenScopes    []string
	AuthorizationEndpointOverride string
	AllowPseudonymous             bool
	StripSignatureHeaders         bool
	AuthorityOverride             string
	AuthServers                   []AuthServer
	AgentServers                  []AgentServer
	Policy                        PolicyConfig
	Access                        AccessConfig
	PersonServer                  PersonServer
	// AllowedSignatureKeySchemes, if non-empty, restricts Signature-Key schemes
	// for this resource (hwk, jwks_uri, jwt). Empty means legacy: all schemes
	// may be used subject to other rules (e.g. allow_pseudonymous for hwk).
	AllowedSignatureKeySchemes []string
	// AllowedJWTTypes, if non-empty, restricts JWT typ inside the jwt Signature-Key
	// scheme (aa-agent+jwt, aa-auth+jwt). Empty means both are allowed when jwt is used.
	AllowedJWTTypes []string
	// AllowInsecureJWTIssuer, when true, allows JWT iss (and related checks in token
	// verification) to use http:// for local development hosts (localhost, 127.0.0.1, ::1,
	// *.localhost) in addition to https://. When false, iss must be https:// (spec default).
	AllowInsecureJWTIssuer bool
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

type AccessConfig struct {
	Require string
}

type PersonServer struct {
	Issuer  string
	JwksURI string
}
