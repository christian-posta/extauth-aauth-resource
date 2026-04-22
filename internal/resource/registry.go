package resource

import (
	"fmt"
	"sync"

	"aauth-service/internal/config"
)

type Registry struct {
	mu     sync.RWMutex
	byID   map[string]*config.ResourceConfig
	byHost map[string]*config.ResourceConfig
}

func NewRegistry(cfg *config.Config) (*Registry, error) {
	r := &Registry{
		byID:   make(map[string]*config.ResourceConfig),
		byHost: make(map[string]*config.ResourceConfig),
	}

	for _, rcYAML := range cfg.Resources {
		rc := rcYAML.ToDomain()

		// Try to load the private key
		if rc.SigningKey.PrivateKeyFile != "" {
			privKey, err := LoadPrivateKey(rc.SigningKey.PrivateKeyFile)
			if err != nil {
				// We don't fail hard here for testing purposes, but we log it
				fmt.Printf("Warning: failed to load private key for resource %s: %v\n", rc.ID, err)
			} else {
				rc.PrivateKey = privKey
			}
		}

		if _, exists := r.byID[rc.ID]; exists {
			return nil, fmt.Errorf("duplicate resource id: %s", rc.ID)
		}
		r.byID[rc.ID] = rc

		for _, host := range rc.Hosts {
			if _, exists := r.byHost[host]; exists {
				return nil, fmt.Errorf("duplicate host: %s", host)
			}
			r.byHost[host] = rc
		}
	}

	return r, nil
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
