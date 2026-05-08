package aauth

// Wire-format error codes used in JSON bodies of token-endpoint and polling
// responses. These constants match the Python reference (aauth/errors.py) so
// Go and Python implementations interoperate at the wire level.
const (
	// Token endpoint error codes (JSON body of 4xx responses).
	ErrCodeInvalidAgentToken    = "invalid_agent_token"
	ErrCodeExpiredAgentToken    = "expired_agent_token"
	ErrCodeInvalidResourceToken = "invalid_resource_token"
	ErrCodeExpiredResourceToken = "expired_resource_token"
	ErrCodeInvalidAuthToken     = "invalid_auth_token"
	ErrCodeServerError          = "server_error"

	// Polling / authorization error codes.
	ErrCodeInteractionRequired = "interaction_required"
	ErrCodeMissionTerminated   = "mission_terminated"
	ErrCodeDenied              = "denied"
	ErrCodeAbandoned           = "abandoned"
	ErrCodeExpired             = "expired"
	ErrCodeInvalidCode         = "invalid_code"
	ErrCodeSlowDown            = "slow_down"
)
