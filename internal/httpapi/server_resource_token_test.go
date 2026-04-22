package httpapi_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"aauth-service/internal/config"
	"aauth-service/internal/httpapi"
	"aauth-service/internal/jwksfetch"
	"aauth-service/internal/policy"
	"aauth-service/internal/resource"
	"aauth-service/pkg/httpsig"
	"aauth-service/pkg/httpsig/structfields"
)

func TestHandleResourceToken(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	cfg.Resources = []config.ResourceConfigYAML{
		{
			ID:                "res-token",
			Issuer:            "https://res.example.com",
			Hosts:             []string{"res.example.com"},
			AllowPseudonymous: true,
			SignatureWindow:   60 * time.Second,
		},
	}

	reg, _ := resource.NewRegistry(cfg)
	// Inject the private key
	rc, _ := reg.ByID("res-token")
	rc.PrivateKey = priv

	mockJwks := jwksfetch.NewMockClient()
	engine := policy.NewDefaultEngine()

	srv := httpapi.NewServer(reg, mockJwks, engine)

	pubBytes := pub
	x64 := base64.RawURLEncoding.EncodeToString(pubBytes)
	sigKeyVal := `sig=hwk;kty="OKP";crv="Ed25519";x="` + x64 + `"`

	headers := map[string][]string{
		"signature-key": {sigKeyVal},
	}

	now := time.Now().Unix()
	params := structfields.Params{
		{Name: "created", Value: now},
		{Name: "alg", Value: "ed25519"},
	}

	signInput := httpsig.SignInput{
		Method:     "POST",
		Authority:  "res.example.com",
		Path:       "/resource/token",
		Headers:    headers,
		Label:      "sig",
		Components: []string{"@method", "@authority", "@path", "signature-key"},
		Params:     params,
		PrivateKey: priv,
		Alg:        "ed25519",
	}

	sigBytes, sigInputStr, _ := httpsig.Sign(signInput)

	reqBody := `{"scope":"read"}`
	req := httptest.NewRequest("POST", "https://res.example.com/resource/token", bytes.NewBufferString(reqBody))
	req.Header.Set("signature-key", sigKeyVal)
	req.Header.Set("signature-input", sigInputStr)
	req.Header.Set("signature", `sig=:`+base64.StdEncoding.EncodeToString(sigBytes)+`:`)

	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v. Body: %s", status, http.StatusOK, rr.Body.String())
	}

	var response struct {
		ResourceToken string `json:"resource_token"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response.ResourceToken == "" {
		t.Errorf("expected a resource token")
	} else {
		// Just a simple sanity check on the token structure
		parts := strings.Split(response.ResourceToken, ".")
		if len(parts) != 3 {
			t.Errorf("expected 3 token parts, got %d", len(parts))
		}
	}
}
