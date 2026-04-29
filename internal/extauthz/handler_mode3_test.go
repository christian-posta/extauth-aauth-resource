package extauthz_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"

	pb "aauth-service/gen/proto"
	"aauth-service/internal/config"
	"aauth-service/internal/extauthz"
	"aauth-service/internal/jwksfetch"
	"aauth-service/internal/policy"
	"aauth-service/internal/resource"
	"aauth-service/pkg/httpsig"
	"aauth-service/pkg/httpsig/structfields"
)

func TestHandlerMode3GateIdentifiedReturnsChallenge(t *testing.T) {
	agentPub, agentPriv, agentServerPriv, handler := newMode3Handler(t)
	req := signedCheckRequest(t, "GET", "/api", "res.example.com", mode3AgentJWT(t, agentPub, agentServerPriv), agentPriv)

	resp, err := handler.Check(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status.Code != 16 {
		t.Fatalf("expected UNAUTHENTICATED, got %v", resp.Status.Code)
	}

	denied := resp.HttpResponse.(*pb.CheckResponse_DeniedResponse).DeniedResponse
	var headerVal string
	for _, h := range denied.Headers {
		if h.Header.Key == "AAuth-Requirement" {
			headerVal = h.Header.Value
			break
		}
	}
	if headerVal == "" {
		t.Fatal("missing AAuth-Requirement")
	}

	dict, err := structfields.ParseDictionary(headerVal)
	if err != nil {
		t.Fatalf("parse header: %v", err)
	}
	if _, ok := dict.Get("auth-server"); ok {
		t.Fatal("auth-server must be absent")
	}
	tokenVal, ok := dict.Get("resource-token")
	if !ok {
		t.Fatal("missing resource-token")
	}
	tokenStr := tokenVal.(structfields.Item).Value.(string)
	if tokenStr == "" {
		t.Fatal("expected non-empty resource-token")
	}
}

func TestHandlerMode3AuthorizedPasses(t *testing.T) {
	agentPub, agentPriv, authServerPriv, handler := newMode3Handler(t)
	req := signedCheckRequest(t, "GET", "/api", "res.example.com", mode3AuthJWT(t, agentPub, authServerPriv), agentPriv)

	resp, err := handler.Check(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status.Code != 0 {
		t.Fatalf("expected OK, got %v", resp.Status.Code)
	}

	okResp := resp.HttpResponse.(*pb.CheckResponse_OkResponse).OkResponse
	found := false
	for _, h := range okResp.Headers {
		if h.Header.Key == "x-aauth-level" && h.Header.Value == "authorized" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("missing x-aauth-level=authorized")
	}
}

func newMode3Handler(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, ed25519.PrivateKey, *extauthz.Handler) {
	t.Helper()

	agentPub, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authServerPub, authServerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, resourcePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	resourceKeyFile := writeTempEd25519Key(t, resourcePriv)

	authServerKey, err := jwk.FromRaw(authServerPub)
	if err != nil {
		t.Fatal(err)
	}
	authServerKey.Set(jwk.KeyIDKey, "server-key-1")

	mockJwks := jwksfetch.NewMockClient()
	set := jwk.NewSet()
	set.AddKey(authServerKey)
	mockJwks.Metadata["https://agents.example.com/.well-known/aauth-agent.json"] = map[string]interface{}{"jwks_uri": "https://agents.example.com/jwks.json"}
	mockJwks.Metadata["https://ps.example.com/.well-known/aauth-access.json"] = map[string]interface{}{"jwks_uri": "https://ps.example.com/jwks.json"}
	mockJwks.Keysets["https://agents.example.com/jwks.json"] = set
	mockJwks.Keysets["https://ps.example.com/jwks.json"] = set

	cfg := &config.Config{
		Resources: []config.ResourceConfigYAML{
			{
				ID:              "res-mode3",
				Issuer:          "https://res.example.com",
				Hosts:           []string{"res.example.com"},
				SigningKey:      config.SigningKeyYAML{Kid: "resource-key-1", PrivateKeyFile: resourceKeyFile},
				SignatureWindow: 60 * time.Second,
				Access:          config.AccessConfigYAML{Require: "auth-token"},
				PersonServer:    config.PersonServerYAML{Issuer: "https://ps.example.com", JwksURI: "https://ps.example.com/jwks.json"},
				AgentServers: []config.AgentServerYAML{
					{Issuer: "https://agents.example.com", JwksURI: "https://agents.example.com/jwks.json"},
				},
			},
		},
	}

	reg, err := resource.NewRegistry(cfg)
	if err != nil {
		t.Fatal(err)
	}
	engine := policy.NewDefaultEngine()
	aauthHandler := extauthz.NewAAuthHandler(engine, mockJwks)
	return agentPub, agentPriv, authServerPriv, extauthz.NewTestHandler(reg, aauthHandler)
}

func writeTempEd25519Key(t *testing.T, priv ed25519.PrivateKey) string {
	t.Helper()

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	path := t.TempDir() + "/resource_key.pem"
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func mode3AgentJWT(t *testing.T, agentPub ed25519.PublicKey, signer ed25519.PrivateKey) string {
	t.Helper()
	agentKeyJWK, _ := jwk.FromRaw(agentPub)
	jwkBytes, _ := json.Marshal(agentKeyJWK)
	var jwkMap map[string]interface{}
	json.Unmarshal(jwkBytes, &jwkMap)

	claims := map[string]interface{}{
		"iss": "https://agents.example.com",
		"dwk": "aauth-agent.json",
		"sub": "test-delegate",
		"aud": "https://res.example.com",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"cnf": map[string]interface{}{
			"jwk": jwkMap,
		},
	}
	return signJWT(t, "aa-agent+jwt", "server-key-1", claims, signer)
}

func mode3AuthJWT(t *testing.T, agentPub ed25519.PublicKey, signer ed25519.PrivateKey) string {
	t.Helper()
	agentKeyJWK, _ := jwk.FromRaw(agentPub)
	jwkBytes, _ := json.Marshal(agentKeyJWK)
	var jwkMap map[string]interface{}
	json.Unmarshal(jwkBytes, &jwkMap)

	const agentID = "aauth:mode3-agent@agents.example.com"

	claims := map[string]interface{}{
		"iss":   "https://ps.example.com",
		"dwk":   "aauth-access.json",
		"sub":   "test-delegate",
		"aud":   "https://res.example.com",
		"agent": agentID,
		"scope": "read:data",
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
		"act":   map[string]interface{}{"sub": agentID},
		"cnf": map[string]interface{}{
			"jwk": jwkMap,
		},
	}
	return signJWT(t, "aa-auth+jwt", "server-key-1", claims, signer)
}

func signJWT(t *testing.T, typ, kid string, claims map[string]interface{}, signer ed25519.PrivateKey) string {
	t.Helper()
	header := map[string]interface{}{
		"typ": typ,
		"alg": "EdDSA",
		"kid": kid,
	}
	headerBytes, _ := json.Marshal(header)
	claimsBytes, _ := json.Marshal(claims)
	unsignedToken := base64.RawURLEncoding.EncodeToString(headerBytes) + "." + base64.RawURLEncoding.EncodeToString(claimsBytes)
	sig := ed25519.Sign(signer, []byte(unsignedToken))
	return unsignedToken + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func signedCheckRequest(t *testing.T, method, path, authority, jwt string, signer ed25519.PrivateKey) *pb.CheckRequest {
	t.Helper()

	sigKeyVal := `sig=jwt;jwt="` + jwt + `"`
	headers := map[string][]string{
		"signature-key": {sigKeyVal},
	}
	params := structfields.Params{
		{Name: "created", Value: time.Now().Unix()},
		{Name: "alg", Value: "ed25519"},
	}
	signInput := httpsig.SignInput{
		Method:     method,
		Authority:  authority,
		Path:       path,
		Headers:    headers,
		Label:      "sig",
		Components: []string{"@method", "@authority", "@path", "signature-key"},
		Params:     params,
		PrivateKey: signer,
		Alg:        "ed25519",
	}

	sigBytes, sigInputStr, err := httpsig.Sign(signInput)
	if err != nil {
		t.Fatal(err)
	}

	return &pb.CheckRequest{
		Attributes: &pb.AttributeContext{
			ContextExtensions: map[string]string{
				"aauth_resource_id": "res-mode3",
			},
			Request: &pb.AttributeContext_Request{
				Http: &pb.AttributeContext_HttpRequest{
					Method: method,
					Host:   authority,
					Path:   path,
					Headers: map[string]string{
						"signature-key":   sigKeyVal,
						"signature-input": sigInputStr,
						"signature":       `sig=:` + base64.StdEncoding.EncodeToString(sigBytes) + `:`,
					},
				},
			},
		},
	}
}
