package agent

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// ExchangeResourceTokenOptions is the single entry-point configuration for the
// full three-party resource-token exchange flow.
type ExchangeResourceTokenOptions struct {
	ResourceToken   string
	Signer          *RequestSigner
	Scopes          []string
	PSMetadataURL   string
	HTTPClient      *http.Client
	OnInteraction   InteractionCallback
	OnClarification ClarificationCallback
	MaxPolls        int
	Logger          *slog.Logger
	Clock           func() time.Time
}

// ExchangeResourceToken wires together a Poller and a TokenExchanger to perform
// the complete three-party exchange: resource token → PS token_endpoint → auth token.
func ExchangeResourceToken(ctx context.Context, opts ExchangeResourceTokenOptions) (*ExchangeResult, error) {
	poller := NewPoller(PollerOptions{
		HTTPClient:      opts.HTTPClient,
		MaxAttempts:     opts.MaxPolls,
		OnInteraction:   opts.OnInteraction,
		OnClarification: opts.OnClarification,
		Clock:           opts.Clock,
		Logger:          opts.Logger,
		Signer:          opts.Signer,
	})

	exchanger, err := NewTokenExchanger(ExchangerOptions{
		HTTPClient:    opts.HTTPClient,
		PSMetadataURL: opts.PSMetadataURL,
		Poller:        poller,
		Logger:        opts.Logger,
	})
	if err != nil {
		return nil, fmt.Errorf("orchestrator: create exchanger: %w", err)
	}

	return exchanger.Exchange(ctx, ExchangeRequest{
		ResourceToken: opts.ResourceToken,
		Signer:        opts.Signer,
		Scopes:        opts.Scopes,
	})
}
