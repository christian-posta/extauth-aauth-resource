package extauthz

import (
	"aauth-service/internal/resource"
)

// NewTestHandler creates a handler with injected dependencies for testing
func NewTestHandler(reg *resource.Registry, aauth *AAuthHandler) *Handler {
	return &Handler{
		registry: reg,
		aauth:    aauth,
	}
}
