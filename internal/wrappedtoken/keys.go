package wrappedtoken

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"strings"

	"aauth-service/internal/config"
)

// Registry holds the resolved AES-256 key for each resource that uses resource-managed access.
type Registry struct {
	keys map[string][]byte // resourceID → 32-byte key
}

// NewRegistry builds a Registry from resource configs. For each resource with
// access.require=interaction, it resolves (or generates) a 32-byte AES key.
func NewRegistry(resources []*config.ResourceConfig) (*Registry, error) {
	r := &Registry{keys: make(map[string][]byte)}
	for _, rc := range resources {
		if rc.Access.Require != "interaction" {
			continue
		}
		key, err := resolveKey(rc)
		if err != nil {
			return nil, fmt.Errorf("resource %s: opaque_token_key: %w", rc.ID, err)
		}
		r.keys[rc.ID] = key
	}
	return r, nil
}

// ForResource returns the 32-byte AES key for the given resource ID.
// Returns false if the resource is not registered (not an interaction-mode resource).
func (r *Registry) ForResource(resourceID string) ([]byte, bool) {
	k, ok := r.keys[resourceID]
	return k, ok
}

func resolveKey(rc *config.ResourceConfig) ([]byte, error) {
	kc := rc.OpaqueTokenKey
	if kc.KeyFile != "" {
		return loadKeyFile(rc.ID, kc.KeyFile)
	}
	if kc.KeyB64 != "" {
		return decodeBase64Key(rc.ID, kc.KeyB64)
	}
	// Ephemeral: generate at startup with a clear warning.
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("rand: %w", err)
	}
	log.Printf("WARNING: resource %q has no opaque_token_key configured — using ephemeral key; "+
		"all AAuth-Access tokens will be invalidated on service restart", rc.ID)
	return key, nil
}

func loadKeyFile(resourceID, path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	// File may be raw 32 bytes or base64-encoded text (e.g. from `openssl rand -base64 32`).
	trimmed := strings.TrimSpace(string(data))
	if len(data) == 32 {
		return data, nil
	}
	return decodeBase64Key(resourceID, trimmed)
}

func decodeBase64Key(resourceID, encoded string) ([]byte, error) {
	// Accept both standard and URL-safe base64, with or without padding.
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		key, err = base64.URLEncoding.DecodeString(encoded)
		if err != nil {
			key, err = base64.RawStdEncoding.DecodeString(encoded)
			if err != nil {
				key, err = base64.RawURLEncoding.DecodeString(encoded)
				if err != nil {
					return nil, fmt.Errorf("resource %s: could not base64-decode opaque_token_key", resourceID)
				}
			}
		}
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("resource %s: opaque_token_key must be 32 bytes, decoded %d", resourceID, len(key))
	}
	return key, nil
}
