package transport

import (
	"net/http"

	"aauth-service/pkg/aauth/agent"
)

// SigningTransport is an http.RoundTripper that signs every outgoing request.
type SigningTransport struct {
	Base       http.RoundTripper
	Signer     *agent.RequestSigner
	Components []string
}

// NewSigningTransport creates a SigningTransport. If base is nil, http.DefaultTransport is used.
func NewSigningTransport(base http.RoundTripper, signer *agent.RequestSigner, comps []string) *SigningTransport {
	if base == nil {
		base = http.DefaultTransport
	}
	return &SigningTransport{
		Base:       base,
		Signer:     signer,
		Components: comps,
	}
}

// RoundTrip clones the request, signs it, then dispatches it via the base transport.
func (t *SigningTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	cloned := req.Clone(req.Context())
	if cloned.Header == nil {
		cloned.Header = make(http.Header)
	}

	if err := t.Signer.Sign(req.Context(), cloned, t.Components); err != nil {
		return nil, err
	}

	return t.Base.RoundTrip(cloned)
}
