package http

const (
	StatusPending    = "pending"
	StatusInteracting = "interacting"
	StatusCompleted  = "completed"

	CodeSuccess   = 200
	CodeDenied    = 403
	CodeExpired   = 408
	CodeCancelled = 410
)

// DeferredResponse represents a 202 Accepted response body.
// Location and RetryAfter are parsed from response headers, not the body.
type DeferredResponse struct {
	Status      string `json:"status"`
	Location    string
	RetryAfter  int
	Requirement   string `json:"requirement,omitempty"`
	URL           string `json:"url,omitempty"`
	Code          string `json:"code,omitempty"`
	Clarification string `json:"clarification,omitempty"`
	Token         string `json:"token,omitempty"`
}
