package policy

import (
	"context"

	"policy_engine/internal/aauth"
)

type Header struct {
	Key   string
	Value string
}

type DenialDetails struct {
	StatusCode int
	ErrorCode  string
}

type Decision struct {
	Allow   bool
	Reason  string
	Headers []Header
	Denial  *DenialDetails
}

type PolicyInput struct {
	Resource   string
	Method     string
	Path       string
	Host       string
	Identity   aauth.Identity
	Headers    map[string]string
	ContextExt map[string]string
}

type Engine interface {
	Name() string
	Decide(ctx context.Context, in PolicyInput) (Decision, error)
}
