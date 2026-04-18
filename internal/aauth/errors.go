package aauth

import "errors"

var (
	ErrMissingSignature     = errors.New("missing_signature")
	ErrInvalidSignature     = errors.New("invalid_signature")
	ErrInvalidInput         = errors.New("invalid_input")
	ErrUnsupportedAlgorithm = errors.New("unsupported_algorithm")
	ErrInvalidKey           = errors.New("invalid_key")
	ErrUnknownKey           = errors.New("unknown_key")
	ErrInvalidJWT           = errors.New("invalid_jwt")
	ErrExpiredJWT           = errors.New("expired_jwt")
	ErrInvalidToken         = errors.New("invalid_token")
	ErrInsufficientScope    = errors.New("insufficient_scope")
	ErrUnsupportedScheme    = errors.New("unsupported_scheme")
)
