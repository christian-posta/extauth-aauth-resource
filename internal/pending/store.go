package pending

import "time"

// State represents the lifecycle of a pending interaction request.
type State string

const (
	StatePending     State = "pending"
	StateInteracting State = "interacting"
	StateComplete    State = "complete"
	StateFailed      State = "failed"
	StateConsumed    State = "consumed" // agent received AAuth-Access; future polls return 410
)

// Entry is a single in-flight resource-managed authorization.
type Entry struct {
	ID           string
	Code         string    // single-use interaction code
	ResourceID   string
	AgentID      string
	AgentJKT     string
	Scope        string
	CreatedAt    time.Time
	ExpiresAt    time.Time
	State        State
	OAuthState   string // random state token for CSRF protection
	PKCEVerifier string // PKCE code_verifier (empty if PKCE disabled)
	OpaqueToken  string // set when State==complete; the wrapped AAuth-Access value
	LastErr      string
}

// Store manages pending interaction entries.
type Store interface {
	// Create stores a new pending entry. Returns error if ID or Code already exists.
	Create(e *Entry) error
	// ByID looks up an entry by its pending ID (used for polling).
	ByID(id string) (*Entry, bool)
	// ByCode looks up an entry by its single-use interaction code.
	ByCode(code string) (*Entry, bool)
	// MarkInteracting transitions pending → interacting (user arrived at interaction URL).
	MarkInteracting(id string) error
	// Complete transitions interacting → complete and stores the wrapped opaque token.
	Complete(id, opaqueToken string) error
	// Fail records a terminal error.
	Fail(id, errMsg string) error
	// Consume transitions complete → consumed. Returns the entry so the caller can read OpaqueToken.
	// After Consume, ByID returns the entry with State==consumed so polls return 410.
	Consume(id string) (*Entry, error)
	// ByOAuthState looks up an entry by its OAuth state parameter (used in CSRF validation).
	ByOAuthState(state string) *Entry
}
