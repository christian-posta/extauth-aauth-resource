package transport

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"aauth-service/pkg/aauth/agent"
)

func newTestSigner(t *testing.T) *agent.RequestSigner {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	s, err := agent.NewRequestSigner(agent.SignerOptions{
		AgentID:   "aauth:transport-test@example.com",
		KeyID:     "key-1",
		Signer:    priv,
		Algorithm: "ed25519",
		Clock:     func() time.Time { return time.Now() },
	})
	if err != nil {
		t.Fatalf("NewRequestSigner: %v", err)
	}
	return s
}

func TestSigningTransport_HeadersPresent(t *testing.T) {
	var capturedReq *http.Request

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedReq = r
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	signer := newTestSigner(t)
	comps := []string{"@method", "@authority", "@path", "signature-key"}

	client := &http.Client{
		Transport: NewSigningTransport(nil, signer, comps),
	}

	resp, err := client.Get(srv.URL + "/test")
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	defer resp.Body.Close()

	if capturedReq == nil {
		t.Fatal("server did not receive request")
	}

	if capturedReq.Header.Get("Signature") == "" {
		t.Error("missing Signature header on proxied request")
	}
	if capturedReq.Header.Get("Signature-Input") == "" {
		t.Error("missing Signature-Input header on proxied request")
	}
	if capturedReq.Header.Get("Signature-Key") == "" {
		t.Error("missing Signature-Key header on proxied request")
	}
}

func TestSigningTransport_DoesNotMutateOriginal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	signer := newTestSigner(t)
	comps := []string{"@method", "@authority", "@path", "signature-key"}

	transport := NewSigningTransport(nil, signer, comps)

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/check", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	originalHeaderCount := len(req.Header)

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer resp.Body.Close()

	if len(req.Header) != originalHeaderCount {
		t.Errorf("RoundTrip mutated the original request headers (before=%d, after=%d)",
			originalHeaderCount, len(req.Header))
	}
}

func TestNewSigningTransport_DefaultBase(t *testing.T) {
	signer := newTestSigner(t)
	st := NewSigningTransport(nil, signer, nil)
	if st.Base == nil {
		t.Error("Base should default to http.DefaultTransport")
	}
}
