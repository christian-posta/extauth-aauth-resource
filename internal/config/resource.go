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

	// Mode 2 (resource-managed / OAuth bridge) fields.
	OAuthBridge     *OAuthBridgeConfig  // nil unless access.require=interaction
	OpaqueTokenKey  OpaqueTokenKeyConfig
	InteractionTTL  time.Duration // default 15m when zero
	SuccessRedirect string        // optional URL shown/redirected to after OAuth completes
}

// OAuthBridgeConfig holds the upstream OAuth provider settings used in Mode 2.
type OAuthBridgeConfig struct {
	AuthorizeURL    string
	TokenURL        string
	ClientID        string
	ClientSecret    string
	Scopes          []string
	Audience        string
	UsePKCE         bool
	RedirectURIBase string            // e.g. "http://localhost:3001"; callback = base+"/oauth/{rid}/callback"
	ExtraAuthParams map[string]string // appended to the authorization URL
}

// OpaqueTokenKeyConfig specifies how to load the AES-256 key for AAuth-Access tokens.
type OpaqueTokenKeyConfig struct {
	KeyFile string // path to a file containing a base64-encoded 32-byte key
	KeyB64  string // inline base64-encoded 32-byte key (alternative to KeyFile)
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
