package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"aauth-service/pkg/aauth/headers"
	ahttp "aauth-service/pkg/aauth/http"
)

// InteractionCallback is called when the server signals status=interacting or
// requirement=interaction, so the agent can direct a person to the given URL.
type InteractionCallback func(ctx context.Context, url, code string) error

// ClarificationCallback is called when the server requests clarification.
// The returned answer string is POSTed back; an empty string skips the POST.
type ClarificationCallback func(ctx context.Context, prompt string) (answer string, err error)

// ProgressFunc is called on each poll attempt.
type ProgressFunc func(attempt int, status string)

// PollerOptions configures a Poller.
type PollerOptions struct {
	HTTPClient      *http.Client
	MaxAttempts     int
	InitialDelay    time.Duration
	MaxDelay        time.Duration
	OnInteraction   InteractionCallback
	OnClarification ClarificationCallback
	OnProgress      ProgressFunc
	Clock           func() time.Time
	Logger          *slog.Logger
	// Signer signs the clarification POST so the PS can authenticate it as
	// originating from the same agent that initiated the deferred exchange.
	Signer *RequestSigner
}

// PollResult holds the outcome of a completed poll sequence.
type PollResult struct {
	Success   bool
	AuthToken string
	Status    string
	Error     string
}

// Poller implements the deferred-response state machine (spec §10.6 / §12.4).
type Poller struct {
	client          *http.Client
	maxAttempts     int
	initialDelay    time.Duration
	maxDelay        time.Duration
	onInteraction   InteractionCallback
	onClarification ClarificationCallback
	onProgress      ProgressFunc
	clock           func() time.Time
	logger          *slog.Logger
	signer          *RequestSigner
}

// NewPoller constructs a Poller with defaults applied.
func NewPoller(opts PollerOptions) *Poller {
	client := opts.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	maxAttempts := opts.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = 20
	}
	initialDelay := opts.InitialDelay
	if initialDelay <= 0 {
		initialDelay = 2 * time.Second
	}
	maxDelay := opts.MaxDelay
	if maxDelay <= 0 {
		maxDelay = 30 * time.Second
	}
	clock := opts.Clock
	if clock == nil {
		clock = time.Now
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Poller{
		client:          client,
		maxAttempts:     maxAttempts,
		initialDelay:    initialDelay,
		maxDelay:        maxDelay,
		onInteraction:   opts.OnInteraction,
		onClarification: opts.OnClarification,
		onProgress:      opts.OnProgress,
		clock:           clock,
		logger:          logger,
		signer:          opts.Signer,
	}
}

// Poll blocks until the deferred flow resolves or ctx is cancelled.
// pollingURL is the value from the Location header of a 202 Accepted response.
func (p *Poller) Poll(ctx context.Context, pollingURL string) (*PollResult, error) {
	for attempt := 0; attempt < p.maxAttempts; attempt++ {
		select {
		case <-ctx.Done():
			return &PollResult{
				Success: false,
				Status:  "cancelled",
				Error:   ctx.Err().Error(),
			}, ctx.Err()
		default:
		}

		p.logger.DebugContext(ctx, "polling", "attempt", attempt+1, "url", pollingURL)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, pollingURL, nil)
		if err != nil {
			return nil, fmt.Errorf("poller: build request: %w", err)
		}

		resp, err := p.client.Do(req)
		if err != nil {
			return &PollResult{
				Success: false,
				Status:  "error",
				Error:   fmt.Sprintf("network error: %v", err),
			}, nil
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		status := resp.StatusCode

		if p.onProgress != nil {
			p.onProgress(attempt, strconv.Itoa(status))
		}

		switch {
		case status == http.StatusOK:
			return p.handleSuccess(body, resp)

		case status == http.StatusForbidden:
			return p.handleTerminal(body, "denied"), nil

		case status == http.StatusRequestTimeout:
			return p.handleTerminal(body, "expired"), nil

		case status == http.StatusGone:
			return p.handleTerminal(body, "cancelled"), nil

		case status == http.StatusAccepted:
			var deferred ahttp.DeferredResponse
			if len(body) > 0 {
				_ = json.Unmarshal(body, &deferred)
			}
			deferred.Location = resp.Header.Get("Location")
			retryAfter, retryAfterPresent := parseRetryAfter(resp.Header.Get("Retry-After"), p.clock)
			if !retryAfterPresent {
				retryAfter = p.backoffDelay(attempt)
			}

			aauthReqHdr := resp.Header.Get("AAuth-Requirement")
			requirement, interactionURLFromHdr, interactionCodeFromHdr := parseRequirementHeader(aauthReqHdr)
			if requirement == "" {
				requirement = deferred.Requirement
			}

			switch deferred.Status {
			case ahttp.StatusCompleted:
				if deferred.Token != "" {
					return &PollResult{Success: true, AuthToken: deferred.Token, Status: ahttp.StatusCompleted}, nil
				}

			case ahttp.StatusInteracting:
				p.logger.DebugContext(ctx, "user has arrived at interaction endpoint")

			case ahttp.StatusPending:
				if requirement == "clarification" && deferred.Clarification != "" && p.onClarification != nil {
					answer, err := p.onClarification(ctx, deferred.Clarification)
					if err == nil && answer != "" {
						_ = p.postClarification(ctx, pollingURL, answer)
					}
				}
			}

			// Spec §10.6: fire OnInteraction only on the first poll, not after a 429 retry.
			if attempt == 0 && requirement == "interaction" && deferred.Code != "" && p.onInteraction != nil {
				code := deferred.Code
				if interactionCodeFromHdr != "" {
					code = interactionCodeFromHdr
				}
				composedURL := composeInteractionURL(interactionURLFromHdr, deferred.URL, pollingURL, code)
				if err := p.onInteraction(ctx, composedURL, code); err != nil {
					p.logger.WarnContext(ctx, "OnInteraction callback error", "error", err)
				}
			}

			if err := p.sleepWithContext(ctx, retryAfter); err != nil {
				return &PollResult{Success: false, Status: "cancelled", Error: err.Error()}, err
			}
			continue

		case status == http.StatusTooManyRequests:
			retryAfter, retryAfterPresent := parseRetryAfter(resp.Header.Get("Retry-After"), p.clock)
			if !retryAfterPresent {
				retryAfter = p.backoffDelay(attempt)
			}
			p.logger.DebugContext(ctx, "rate limited", "retry_after", retryAfter)
			if err := p.sleepWithContext(ctx, retryAfter); err != nil {
				return &PollResult{Success: false, Status: "cancelled", Error: err.Error()}, err
			}
			continue

		case status >= 500:
			// Transient server errors — back off and retry
			retryAfter, retryAfterPresent := parseRetryAfter(resp.Header.Get("Retry-After"), p.clock)
			if !retryAfterPresent {
				retryAfter = p.backoffDelay(attempt)
			}
			p.logger.WarnContext(ctx, "server error, retrying", "status", status, "retry_after", retryAfter)
			if err := p.sleepWithContext(ctx, retryAfter); err != nil {
				return &PollResult{Success: false, Status: "cancelled", Error: err.Error()}, err
			}
			continue

		default:
			return &PollResult{
				Success: false,
				Status:  "error",
				Error:   fmt.Sprintf("unexpected HTTP status %d", status),
			}, nil
		}
	}

	return &PollResult{
		Success: false,
		Status:  "error",
		Error:   "max attempts exceeded",
	}, nil
}

func (p *Poller) handleSuccess(body []byte, resp *http.Response) (*PollResult, error) {
	var result struct {
		AuthToken   string `json:"auth_token"`
		AccessToken string `json:"access_token"`
		Token       string `json:"token"`
	}
	if len(body) > 0 {
		_ = json.Unmarshal(body, &result)
	}
	token := result.AuthToken
	if token == "" {
		token = result.AccessToken
	}
	if token == "" {
		token = result.Token
	}
	// Also check Authorization header as a fallback
	if token == "" {
		authHdr := resp.Header.Get("Authorization")
		if strings.HasPrefix(authHdr, "Bearer ") {
			token = strings.TrimPrefix(authHdr, "Bearer ")
		}
	}
	return &PollResult{Success: true, AuthToken: token, Status: ahttp.StatusCompleted}, nil
}

func (p *Poller) handleTerminal(body []byte, defaultErr string) *PollResult {
	var errBody struct {
		Error string `json:"error"`
	}
	if len(body) > 0 {
		_ = json.Unmarshal(body, &errBody)
	}
	errStr := errBody.Error
	if errStr == "" {
		errStr = defaultErr
	}
	return &PollResult{Success: false, Status: defaultErr, Error: errStr}
}

func (p *Poller) postClarification(ctx context.Context, url, answer string) error {
	payload, err := json.Marshal(map[string]string{"clarification_response": answer})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	digest := sha256.Sum256(payload)
	req.Header.Set("Content-Digest", "sha-256=:"+base64.StdEncoding.EncodeToString(digest[:])+":")
	if p.signer != nil {
		comps := []string{"@method", "@authority", "@path", "content-type", "content-digest"}
		if err := p.signer.Sign(ctx, req, comps); err != nil {
			return fmt.Errorf("poller: sign clarification POST: %w", err)
		}
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// parseRequirementHeader returns (requirementType, url, code) from an AAuth-Requirement
// header value. Returns zero values when the header is empty or malformed.
func parseRequirementHeader(headerValue string) (string, string, string) {
	if headerValue == "" {
		return "", "", ""
	}
	reqs, err := headers.ParseAAuthRequirement(headerValue)
	if err != nil || len(reqs) == 0 {
		return "", "", ""
	}
	r := reqs[0]
	switch v := r.(type) {
	case headers.InteractionReq:
		return v.Type(), v.URL, v.Code
	default:
		return r.Type(), "", ""
	}
}

// composeInteractionURL builds the user-facing URL the agent surfaces to the
// human, mirroring Python's _extract_interaction_url. Preference order:
// AAuth-Requirement url, body url, fall back to pollingURL.
func composeInteractionURL(headerURL, bodyURL, pollingURL, code string) string {
	endpoint := headerURL
	if endpoint == "" {
		endpoint = bodyURL
	}
	if endpoint == "" {
		return pollingURL
	}
	if code == "" {
		return endpoint
	}
	sep := "?"
	if strings.Contains(endpoint, "?") {
		sep = "&"
	}
	return endpoint + sep + "code=" + code
}

// backoffDelay computes exponential backoff with jitter: min(initialDelay*2^attempt + jitter, maxDelay).
func (p *Poller) backoffDelay(attempt int) time.Duration {
	exp := math.Pow(2, float64(attempt))
	delay := time.Duration(float64(p.initialDelay) * exp)
	// Add up to 20% jitter
	jitter := time.Duration(rand.Int63n(int64(p.initialDelay/5 + 1)))
	delay += jitter
	if delay > p.maxDelay {
		delay = p.maxDelay
	}
	return delay
}

func (p *Poller) sleepWithContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// parseRetryAfter parses the Retry-After header value.
// The value may be an integer (seconds) or an HTTP-date string (RFC 7231 §7.1.3).
// Returns (duration, true) when the header is present and parseable.
// Returns (0, false) when absent or unparseable so callers can distinguish
// "server said wait 0 seconds" from "server provided no guidance".
func parseRetryAfter(val string, clock func() time.Time) (time.Duration, bool) {
	if val == "" {
		return 0, false
	}
	// Try integer seconds first
	if secs, err := strconv.Atoi(strings.TrimSpace(val)); err == nil {
		return time.Duration(secs) * time.Second, true
	}
	// Try HTTP-date (RFC 1123 format per RFC 7231 §7.1.3)
	if t, err := http.ParseTime(val); err == nil {
		now := clock()
		d := t.Sub(now)
		if d < 0 {
			return 0, true
		}
		return d, true
	}
	return 0, false
}
