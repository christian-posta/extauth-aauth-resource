package aauth

import "errors"

// AAuthError is the base interface for all typed AAuth errors.
// It extends the standard error interface with a Code method that returns
// the machine-readable error code suitable for use in wire protocol messages.
type AAuthError interface {
	error
	// Code returns the machine-readable error code (e.g. "invalid_signature").
	Code() string
}

// aAuthErr is the concrete implementation of AAuthError backed by a plain errors.New value.
type aAuthErr struct {
	msg string
}

func (e *aAuthErr) Error() string { return e.msg }
func (e *aAuthErr) Code() string  { return e.msg }

func newAAuthErr(code string) *aAuthErr {
	return &aAuthErr{msg: code}
}

var (
	ErrMissingSignature   = newAAuthErr("missing_signature")
	ErrInvalidSignature   = newAAuthErr("invalid_signature")
	ErrInvalidInput       = newAAuthErr("invalid_input")
	ErrUnsupportedAlgorithm = newAAuthErr("unsupported_algorithm")
	ErrInvalidKey         = newAAuthErr("invalid_key")
	ErrUnknownKey         = newAAuthErr("unknown_key")
	ErrInvalidJWT         = newAAuthErr("invalid_jwt")
	ErrExpiredJWT         = newAAuthErr("expired_jwt")
	ErrInvalidToken       = newAAuthErr("invalid_token")
	ErrInsufficientScope  = newAAuthErr("insufficient_scope")

	ErrUnsupportedScheme            = newAAuthErr("unsupported_scheme")
	ErrDisallowedSignatureKeyScheme = newAAuthErr("disallowed_signature_key_scheme")
	ErrDisallowedJWTType            = newAAuthErr("disallowed_jwt_type")

	// ErrInvalidIdentifier is returned when an agent or server identifier fails
	// validation per spec §5.1 and §12.9.1.
	ErrInvalidIdentifier = newAAuthErr("invalid_identifier")

	// ErrChallengeRequired is returned when a request must be accompanied by an
	// AAuth challenge response but none was provided.
	ErrChallengeRequired = newAAuthErr("challenge_required")

	// ErrInteractionTimeout is returned when the user interaction window expired
	// before the agent polled for a result.
	ErrInteractionTimeout = newAAuthErr("interaction_timeout")

	// ErrDenied is returned when an access request is explicitly denied by the
	// person server, access server, or resource.
	ErrDenied = newAAuthErr("denied")
)

// sentinel is a package-level var used only for errors.Is compat with tests
// that previously compared to the old plain errors.New values.
// The aAuthErr.Is method makes errors.Is work transparently.
var _ = errors.New // retain import

func (e *aAuthErr) Is(target error) bool {
	if t, ok := target.(*aAuthErr); ok {
		return e.msg == t.msg
	}
	return false
}
