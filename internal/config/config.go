package config

import (
	"fmt"
	"os"
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
	AuthorizationEndpoint         string            `yaml:"authorization_endpoint"`
	AllowPseudonymous             bool              `yaml:"allow_pseudonymous"`
	StripSignatureHeaders         bool              `yaml:"strip_signature_headers"`
	AuthServers                   []AuthServerYAML  `yaml:"auth_servers"`
	AgentServers                  []AgentServerYAML `yaml:"agent_servers"`
	Policy                        PolicyConfigYAML  `yaml:"policy"`
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
		AuthorizationEndpoint:         c.AuthorizationEndpoint,
		AllowPseudonymous:             c.AllowPseudonymous,
		StripSignatureHeaders:         c.StripSignatureHeaders,
		AuthServers:                   authServers,
		AgentServers:                  agentServers,
		Policy:                        PolicyConfig{Name: c.Policy.Name},
	}
}
