package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds the root application configuration
type Config struct {
	Listen struct {
		GRPC string `yaml:"grpc"`
		HTTP string `yaml:"http"`
	} `yaml:"listen"`

	JwksCache struct {
		SuccessTTL time.Duration `yaml:"success_ttl"`
		ErrorTTL   time.Duration `yaml:"error_ttl"`
		MaxEntries int           `yaml:"max_entries"`
	} `yaml:"jwks_cache"`

	Resources []ResourceConfigYAML `yaml:"resources"`

	// Derived from flags, keep this around for backwards compatibility with the stub main.go
	Port int `yaml:"-"`
}

// ResourceConfigYAML mirrors ResourceConfig but handles YAML mapping
type ResourceConfigYAML struct {
	ID                            string            `yaml:"id"`
	Issuer                        string            `yaml:"issuer"`
	Hosts                         []string          `yaml:"hosts"`
	SigningKey                    SigningKeyYAML    `yaml:"signing_key"`
	SignatureWindow               time.Duration     `yaml:"signature_window"`
	AdditionalSignatureComponents []string          `yaml:"additional_signature_components"`
	SupportedScopes               []string          `yaml:"supported_scopes"`
	ScopeDescriptions             map[string]string `yaml:"scope_descriptions"`
	DefaultResourceTokenScopes    []string          `yaml:"default_resource_token_scopes"`
	AuthorizationEndpoint         string            `yaml:"authorization_endpoint"`
	AuthorizationEndpointOverride string            `yaml:"authorization_endpoint_override"`
	AllowPseudonymous             bool              `yaml:"allow_pseudonymous"`
	StripSignatureHeaders         bool              `yaml:"strip_signature_headers"`
	AuthorityOverride             string            `yaml:"authority_override"`
	AuthServers                   []AuthServerYAML  `yaml:"auth_servers"`
	AgentServers                  []AgentServerYAML `yaml:"agent_servers"`
	Policy                        PolicyConfigYAML  `yaml:"policy"`
	Access                        AccessConfigYAML  `yaml:"access"`
	PersonServer                  PersonServerYAML  `yaml:"person_server"`
	AllowedSignatureKeySchemes    []string          `yaml:"allowed_signature_key_schemes"`
	AllowedJWTTypes               []string          `yaml:"allowed_jwt_types"`
	// AllowInsecureJWTIssuer: see ResourceConfig.
	AllowInsecureJWTIssuer bool `yaml:"allow_insecure_jwt_issuer"`
}

type SigningKeyYAML struct {
	Kid            string `yaml:"kid"`
	Alg            string `yaml:"alg"`
	PrivateKeyFile string `yaml:"private_key_file"`
}

type AuthServerYAML struct {
	Issuer  string `yaml:"issuer"`
	JwksURI string `yaml:"jwks_uri"`
}

type AgentServerYAML struct {
	Issuer  string `yaml:"issuer"`
	JwksURI string `yaml:"jwks_uri"`
}

type PolicyConfigYAML struct {
	Name string `yaml:"name"`
}

type AccessConfigYAML struct {
	Require string `yaml:"require"`
}

type PersonServerYAML struct {
	Issuer  string `yaml:"issuer"`
	JwksURI string `yaml:"jwks_uri"`
}

// LoadConfig loads configuration from a YAML file path or falls back to a stub configuration
func LoadConfig() (*Config, error) {
	// For testing/bootstrap, we just return a default if no config is given via env
	cfgPath := os.Getenv("AAUTH_CONFIG")
	if cfgPath == "" {
		return &Config{Port: 7070}, nil
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse yaml: %w", err)
	}

	return &cfg, nil
}

// MapToDomain converts the YAML struct to the domain struct
func (c *ResourceConfigYAML) ToDomain() *ResourceConfig {
	authServers := make([]AuthServer, len(c.AuthServers))
	for i, a := range c.AuthServers {
		authServers[i] = AuthServer{Issuer: a.Issuer, JwksURI: a.JwksURI}
	}

	agentServers := make([]AgentServer, len(c.AgentServers))
	for i, a := range c.AgentServers {
		agentServers[i] = AgentServer{Issuer: a.Issuer, JwksURI: a.JwksURI}
	}

	return &ResourceConfig{
		ID:                            c.ID,
		Issuer:                        c.Issuer,
		Hosts:                         c.Hosts,
		SigningKey:                    SigningKey{Kid: c.SigningKey.Kid, Alg: c.SigningKey.Alg, PrivateKeyFile: c.SigningKey.PrivateKeyFile},
		SignatureWindow:               c.SignatureWindow,
		AdditionalSignatureComponents: c.AdditionalSignatureComponents,
		SupportedScopes:               c.SupportedScopes,
		ScopeDescriptions:             c.ScopeDescriptions,
		DefaultResourceTokenScopes:    normalizeScopeValues(c.DefaultResourceTokenScopes),
		AuthorizationEndpointOverride: firstNonEmpty(c.AuthorizationEndpointOverride, c.AuthorizationEndpoint),
		AllowPseudonymous:             c.AllowPseudonymous,
		StripSignatureHeaders:         c.StripSignatureHeaders,
		AuthorityOverride:             c.AuthorityOverride,
		AuthServers:                   authServers,
		AgentServers:                  agentServers,
		Policy:                        PolicyConfig{Name: c.Policy.Name},
		Access:                        AccessConfig{Require: c.Access.Require},
		PersonServer:                  PersonServer{Issuer: c.PersonServer.Issuer, JwksURI: c.PersonServer.JwksURI},
		AllowedSignatureKeySchemes:    NormalizeAndDedupeTokens(c.AllowedSignatureKeySchemes),
		AllowedJWTTypes:               NormalizeAndDedupeTokens(c.AllowedJWTTypes),
		AllowInsecureJWTIssuer:        c.AllowInsecureJWTIssuer,
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func normalizeScopeValues(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, v := range values {
		scope := strings.TrimSpace(v)
		if scope == "" {
			continue
		}
		if _, ok := seen[scope]; ok {
			continue
		}
		seen[scope] = struct{}{}
		out = append(out, scope)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
