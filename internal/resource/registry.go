package resource

import (
	"fmt"
	"sync"

	"aauth-service/internal/config"
)

type Registry struct {
	mu       sync.RWMutex
	byID     map[string]*config.ResourceConfig
	byHost   map[string]*config.ResourceConfig
	byIssuer map[string][]*config.ResourceConfig
}

func NewRegistry(cfg *config.Config) (*Registry, error) {
	r := &Registry{
		byID:     make(map[string]*config.ResourceConfig),
		byHost:   make(map[string]*config.ResourceConfig),
		byIssuer: make(map[string][]*config.ResourceConfig),
	}

	for _, rcYAML := range cfg.Resources {
		rc := rcYAML.ToDomain()
		autoAddPersonServer(rc)
		if err := config.ValidateResource(rc); err != nil {
			return nil, err
		}

		// Try to load the private key
		if rc.SigningKey.PrivateKeyFile != "" {
			privKey, err := LoadPrivateKey(rc.SigningKey.PrivateKeyFile)
			if err != nil {
				if config.RequiresResourceTokenSigningKey(rc) {
					return nil, fmt.Errorf("resource %s requires a signing key but failed to load private key %q: %w", rc.ID, rc.SigningKey.PrivateKeyFile, err)
				}
				fmt.Printf("Warning: failed to load private key for resource %s: %v\n", rc.ID, err)
			} else {
				rc.PrivateKey = privKey
			}
		}
		if config.RequiresResourceTokenSigningKey(rc) {
			if len(rc.PrivateKey) == 0 {
				return nil, fmt.Errorf("resource %s requires a signing key to mint resource tokens", rc.ID)
			}
			if rc.SigningKey.Kid == "" {
				return nil, fmt.Errorf("resource %s requires signing_key.kid to mint resource tokens", rc.ID)
			}
		}

		if _, exists := r.byID[rc.ID]; exists {
			return nil, fmt.Errorf("duplicate resource id: %s", rc.ID)
		}
		r.byID[rc.ID] = rc
		r.byIssuer[rc.Issuer] = append(r.byIssuer[rc.Issuer], rc)

		for _, host := range rc.Hosts {
			if _, exists := r.byHost[host]; exists {
				return nil, fmt.Errorf("duplicate host: %s", host)
			}
			r.byHost[host] = rc
		}
	}

	return r, nil
}

func autoAddPersonServer(rc *config.ResourceConfig) {
	if rc.PersonServer.Issuer == "" {
		return
	}
	for i := range rc.AuthServers {
		if rc.AuthServers[i].Issuer == rc.PersonServer.Issuer {
			if rc.AuthServers[i].JwksURI == "" && rc.PersonServer.JwksURI != "" {
				rc.AuthServers[i].JwksURI = rc.PersonServer.JwksURI
			}
			return
		}
	}
	rc.AuthServers = append(rc.AuthServers, config.AuthServer{
		Issuer:  rc.PersonServer.Issuer,
		JwksURI: rc.PersonServer.JwksURI,
	})
}

func (r *Registry) ByID(id string) (*config.ResourceConfig, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rc, ok := r.byID[id]
	return rc, ok
}

func (r *Registry) ByHost(host string) (*config.ResourceConfig, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rc, ok := r.byHost[host]
	return rc, ok
}

func (r *Registry) ByIssuer(issuer string) []*config.ResourceConfig {
	r.mu.RLock()
	defer r.mu.RUnlock()
	resources := r.byIssuer[issuer]
	out := make([]*config.ResourceConfig, len(resources))
	copy(out, resources)
	return out
}
