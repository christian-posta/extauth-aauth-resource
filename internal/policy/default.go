package policy

import (
	"context"
)

type DefaultEngine struct{}

func NewDefaultEngine() *DefaultEngine {
	return &DefaultEngine{}
}

func (e *DefaultEngine) Name() string {
	return "default"
}

func (e *DefaultEngine) Decide(ctx context.Context, in PolicyInput) (Decision, error) {
	return Decision{
		Allow:  true,
		Reason: "default allow",
	}, nil
}
