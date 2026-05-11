// agent-client is an all-in-one demo agent client for the AAuth resource service.
//
// It generates the keys it needs, hosts the well-known agent metadata and JWKS
// documents the resource service will discover, signs an HTTP request, and sends
// it through agentgateway. Two modes:
//
//	-mode jwks_uri   Signature-Key references the agent's jwks_uri; the request
//	                 signing key is the JWKS key (identity level: identified).
//	-mode agent-jwt  Signature-Key carries an aa-agent+jwt minted by a long-lived
//	                 agent-server key that binds an ephemeral request signing key
//	                 via cnf.jwk (identity level: identified).
//
// In both modes the agent-client also exposes /echo so it can serve as the
// agentgateway upstream backend for the demo.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/christian-posta/aauth-go-library/pkg/aauth/agent"
)

func main() {
	mode := flag.String("mode", "jwks_uri", "Signing mode: jwks_uri or agent-jwt")
	listen := flag.String("listen", "127.0.0.1:9099", "Address for the agent server (well-known + /echo)")
	issuer := flag.String("issuer", "", "Agent server issuer URL; defaults to http://<listen>")
	agentID := flag.String("agent-id", "aauth:demo@127.0.0.1", "Agent identifier (sub of aa-agent+jwt)")
	target := flag.String("target", "http://localhost:3001/echo", "Target URL to call through agentgateway")
	authority := flag.String("authority", "localhost", "Authority used when signing (must match the resource hosts list)")
	method := flag.String("method", "GET", "HTTP method")
	body := flag.String("body", "", "Optional request body")
	tokenTTL := flag.Duration("token-ttl", 5*time.Minute, "aa-agent+jwt lifetime (agent-jwt mode only)")
	serveOnly := flag.Bool("serve", false, "Start the well-known server and block; do not send a request")
	keystore := flag.String("keystore", "agent-client-keys.json", "Path to persist agent keys; remove the file to rotate")
	flag.Parse()

	if *mode != "jwks_uri" && *mode != "agent-jwt" {
		log.Fatalf("unknown -mode %q (expected jwks_uri or agent-jwt)", *mode)
	}

	iss := *issuer
	if iss == "" {
		iss = "http://" + *listen
	}
	if _, err := url.Parse(iss); err != nil {
		log.Fatalf("invalid -issuer: %v", err)
	}

	ks, err := loadOrCreateKeystore(*keystore)
	if err != nil {
		log.Fatalf("keystore: %v", err)
	}

	srv := &agentServer{
		issuer: iss,
		mode:   *mode,
		reqKID: ks.RequestKID,
		reqPub: ks.RequestPub(),
		asKID:  ks.AgentServerKID,
		asPub:  ks.AgentServerPub(),
		asPriv: ks.AgentServerPriv(),
	}

	// Start the well-known + echo HTTP server. If the port is already bound
	// (e.g. another agent-client process is running with -serve) we just skip
	// it; the existing process is presumed to be serving the same keys from
	// the shared keystore file.
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/aauth-agent.json", srv.handleMetadata)
	mux.HandleFunc("/.well-known/jwks.json", srv.handleJWKS)
	mux.HandleFunc("/echo", srv.handleEcho)
	mux.HandleFunc("/", srv.handleEcho)

	ln, err := net.Listen("tcp", *listen)
	switch {
	case err == nil:
		httpSrv := &http.Server{Addr: *listen, Handler: mux}
		go func() {
			if err := httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
				log.Fatalf("agent server: %v", err)
			}
		}()
		log.Printf("agent server listening on %s", iss)
		log.Printf("  metadata: %s/.well-known/aauth-agent.json", iss)
		log.Printf("      jwks: %s/.well-known/jwks.json", iss)
		log.Printf("      echo: %s/echo", iss)
	case isAddrInUse(err):
		if *serveOnly {
			log.Fatalf("-serve: %s already in use", *listen)
		}
		log.Printf("agent server already running on %s; not starting a second one", *listen)
	default:
		log.Fatalf("listen %s: %v", *listen, err)
	}

	if *serveOnly {
		log.Printf("-serve: not sending a request; press Ctrl-C to exit")
		select {}
	}

	// Build the request signer.
	signerOpts := agent.SignerOptions{
		AgentID:   *agentID,
		KeyID:     ks.RequestKID,
		Signer:    ks.RequestPriv(),
		Algorithm: "ed25519",
	}
	switch *mode {
	case "jwks_uri":
		signerOpts.DiscoveryID = iss
		signerOpts.DWK = "aauth-agent.json"
	case "agent-jwt":
		token, err := mintAgentJWT(srv.asPriv, srv.asKID, iss, *agentID, ks.RequestPub(), *tokenTTL)
		if err != nil {
			log.Fatalf("mint aa-agent+jwt: %v", err)
		}
		signerOpts.Tokens = &agent.TokenStore{AgentToken: token}
	}
	signer, err := agent.NewRequestSigner(signerOpts)
	if err != nil {
		log.Fatalf("build request signer: %v", err)
	}

	// Build the outgoing request.
	var bodyReader io.Reader
	if *body != "" {
		bodyReader = strings.NewReader(*body)
	}
	req, err := http.NewRequest(strings.ToUpper(*method), *target, bodyReader)
	if err != nil {
		log.Fatalf("build request: %v", err)
	}
	req.Host = *authority // what the resource sees as the authority
	if *body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if err := signer.Sign(context.Background(), req, []string{"@method", "@authority", "@path", "signature-key"}); err != nil {
		log.Fatalf("sign request: %v", err)
	}

	fmt.Println("=== signed request ===")
	fmt.Printf("%s %s\n", req.Method, req.URL.String())
	fmt.Printf("Host: %s\n", req.Host)
	for _, h := range []string{"signature-key", "signature-input", "signature"} {
		fmt.Printf("%s: %s\n", h, req.Header.Get(h))
	}
	fmt.Println()

	// Send it.
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("send request: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	fmt.Println("=== response ===")
	fmt.Printf("HTTP/%d.%d %s\n", resp.ProtoMajor, resp.ProtoMinor, resp.Status)
	for k, vs := range resp.Header {
		for _, v := range vs {
			fmt.Printf("%s: %s\n", k, v)
		}
	}
	fmt.Println()
	fmt.Println(string(respBody))

	if resp.StatusCode >= 400 {
		os.Exit(2)
	}
}

// agentServer holds the keys exposed at /.well-known/* and serves /echo.
type agentServer struct {
	issuer string
	mode   string

	// ephemeral request signing key (always)
	reqKID string
	reqPub ed25519.PublicKey

	// long-lived agent server signing key (agent-jwt mode only)
	asKID  string
	asPub  ed25519.PublicKey
	asPriv ed25519.PrivateKey
}

func (s *agentServer) handleMetadata(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":      s.issuer,
		"jwks_uri":    s.issuer + "/.well-known/jwks.json",
		"client_name": "AAuth Hello-World Agent Client",
	})
}

func (s *agentServer) handleJWKS(w http.ResponseWriter, r *http.Request) {
	// Publish both keys regardless of mode. The verifier looks up by kid:
	//   - jwks_uri scheme: request signature key (s.reqKID)
	//   - agent-jwt scheme: aa-agent+jwt signing key (s.asKID); the request
	//     signature is then verified via cnf.jwk inside the JWT.
	// Serving both lets users switch modes without restarting the resource
	// service to expire its 60-second JWKS refetch window.
	set := jwk.NewSet()
	set.AddKey(mustJWK(s.reqPub, s.reqKID))
	set.AddKey(mustJWK(s.asPub, s.asKID))
	data, err := json.Marshal(set)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func (s *agentServer) handleEcho(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	resp := map[string]any{
		"method":  r.Method,
		"path":    r.URL.Path,
		"host":    r.Host,
		"headers": flatHeaders(r.Header),
	}
	if len(body) > 0 {
		resp["body"] = string(body)
	}
	writeJSON(w, http.StatusOK, resp)
}

func mustJWK(pub ed25519.PublicKey, kid string) jwk.Key {
	k, err := jwk.FromRaw(pub)
	if err != nil {
		panic(err)
	}
	_ = k.Set(jwk.KeyIDKey, kid)
	_ = k.Set(jwk.AlgorithmKey, "EdDSA")
	_ = k.Set(jwk.KeyUsageKey, "sig")
	return k
}

// mintAgentJWT signs an aa-agent+jwt that binds the ephemeral request key via cnf.jwk.
func mintAgentJWT(asPriv ed25519.PrivateKey, asKID, iss, sub string, reqPub ed25519.PublicKey, ttl time.Duration) (string, error) {
	cnfJWK, err := publicJWKMap(reqPub)
	if err != nil {
		return "", err
	}
	now := time.Now()
	header := map[string]any{
		"typ": "aa-agent+jwt",
		"alg": "EdDSA",
		"kid": asKID,
	}
	claims := map[string]any{
		"iss": iss,
		"dwk": "aauth-agent.json",
		"sub": sub,
		"iat": now.Unix(),
		"exp": now.Add(ttl).Unix(),
		"cnf": map[string]any{"jwk": cnfJWK},
	}
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signing := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	sig := ed25519.Sign(asPriv, []byte(signing))
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func publicJWKMap(pub ed25519.PublicKey) (map[string]any, error) {
	k, err := jwk.FromRaw(pub)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(k)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func flatHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, vs := range h {
		out[k] = strings.Join(vs, ",")
	}
	return out
}

func shortID() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func isAddrInUse(err error) bool {
	return err != nil && strings.Contains(err.Error(), "address already in use")
}
