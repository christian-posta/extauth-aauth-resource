package sigkey

// Scheme represents the signature key scheme.
type Scheme string

const (
	SchemeHWK     Scheme = "hwk"
	SchemeJWT     Scheme = "jwt"
	SchemeJWKSURI Scheme = "jwks_uri"
	SchemeX509    Scheme = "x509"
)

// Parsed contains the extracted material from the Signature-Key header.
type Parsed struct {
	Scheme Scheme
	KeyID  string // keyid= param when present

	// HWK: inline JWK components
	// We map the raw params directly to a map. The caller converts it to a crypto.PublicKey.
	HWK map[string]interface{}

	// JWT: the JWT string; caller must verify before trusting `cnf.jwk`
	JWT string

	// JWKS URI
	JWKSURI string

	// X509: raw cert bytes, not yet used
	X509 []byte
}
