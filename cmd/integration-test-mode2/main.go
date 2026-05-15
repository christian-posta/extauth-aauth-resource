// integration-test-mode2 exercises the full AAuth Mode 2 (resource-managed OAuth bridge) flow.
//
// It embeds a stub OAuth server that auto-approves codes, so no real browser is needed.
//
// Usage (two-terminal setup):
//
//	Terminal 1 — start the stack:
//	  AAUTH_CONFIG=demo/aauth-config-mode2.yaml ./aauth-service &
//	  agentgateway -f demo/agw-config-mode2.yaml &
//
//	Terminal 2 — run the test driver:
//	  go run ./cmd/integration-test-mode2 \
//	    --grpc 127.0.0.1:7070 \
//	    --resource-issuer http://localhost:3001 \
//	    --resource-id github-api \
//	    --authority localhost:3001 \
//	    --path /api/test \
//	    --stub-oauth-port 19100
//
// The stub OAuth server listens on --stub-oauth-port and auto-issues a token for any code.
// Configure aauth-config with:
//
//	oauth_bridge:
//	  authorize_url: http://localhost:19100/oauth/authorize
//	  token_url:     http://localhost:19100/oauth/token
//	  client_id:     test-client
//	  client_secret: test-secret
//	  redirect_uri_base: http://localhost:3001
package main

import (
	"bufio"
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
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "aauth-service/gen/proto"
	"github.com/christian-posta/aauth-go-library/pkg/httpsig"
	"github.com/christian-posta/aauth-go-library/pkg/httpsig/structfields"
)

func main() {
	grpcAddr := flag.String("grpc", "127.0.0.1:7070", "aauth-service gRPC address")
	resourceIssuer := flag.String("resource-issuer", "http://localhost:8080", "Resource issuer URL (used to build interaction URL)")
	resourceID := flag.String("resource-id", "github-api", "AAuth resource ID")
	authority := flag.String("authority", "localhost:8080", "Signed request authority (Host header)")
	path := flag.String("path", "/api/test", "Path to call on the protected resource")
	stubPort := flag.Int("stub-oauth-port", 19100, "Port for embedded stub OAuth server (ignored when --real-oauth is set)")
	realOAuth := flag.Bool("real-oauth", false, "Skip the stub OAuth server; print the interaction URL and pause for the user to complete a real OAuth flow in their browser")
	viaAgw := flag.String("via-agw", "", "If set, perform Step 4 as an actual HTTP request to this agentgateway URL (e.g. http://localhost:3001) instead of a direct gRPC Check. Proves the agentgateway → ExtAuthZ → upstream backend path end-to-end.")
	flag.Parse()

	// ── 1. Start stub OAuth server (skipped in real-oauth mode) ───────────────
	var stubToken string
	if !*realOAuth {
		stubToken = "stub-access-token-" + randomHex(8)
		stub := newStubOAuthServer(stubToken)
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", *stubPort))
		if err != nil {
			log.Fatalf("stub listen :%d: %v", *stubPort, err)
		}
		go http.Serve(ln, stub) //nolint:errcheck
		log.Printf("[stub] OAuth server on :%d; will issue token: %s", *stubPort, stubToken)
	} else {
		log.Println("[real-oauth] using configured real OAuth provider (e.g. GitHub); no stub started")
	}

	// ── 2. Generate agent key (hwk scheme — bare public key, no agent server needed) ──
	agentPub, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("gen key: %v", err)
	}
	agentPubB64 := base64.RawURLEncoding.EncodeToString(agentPub)
	log.Printf("Agent key generated (hwk scheme)")

	// ── 3. Connect to ExtAuthZ gRPC ───────────────────────────────────────────
	conn, err := grpc.Dial(*grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials())) //nolint:staticcheck
	if err != nil {
		log.Fatalf("grpc dial: %v", err)
	}
	defer conn.Close()
	client := pb.NewAuthorizationClient(conn)
	log.Printf("Connected to %s", *grpcAddr)

	// ── 4. Step 1: initial request → 202 + interaction challenge ─────────────
	log.Println("\n─── Step 1: initial request (expect 202 + AAuth-Requirement) ───")
	resp1, _, err := signedCheck(client, *resourceID, *authority, *path, agentPubB64, agentPriv, nil)
	if err != nil {
		log.Fatalf("check step1: %v", err)
	}
	denied1, ok := resp1.HttpResponse.(*pb.CheckResponse_DeniedResponse)
	if !ok || denied1.DeniedResponse.Status.Code != pb.StatusCode_Accepted {
		printResponse("step1", resp1)
		log.Fatalf("expected 202 Accepted")
	}
	code, locationURL := parseInteractionChallenge(denied1.DeniedResponse.Headers)
	if code == "" {
		log.Fatalf("could not parse interaction code from AAuth-Requirement header")
	}
	log.Printf("  interaction code: %s", code)
	log.Printf("  polling URL: %s", locationURL)

	// ── 5. Step 2: browser drives the OAuth flow ─────────────────────────────
	interactionURL := fmt.Sprintf("%s/interaction?code=%s", *resourceIssuer, code)
	if *realOAuth {
		log.Println("\n─── Step 2: open this URL in your browser, complete the OAuth flow, then press Enter ───")
		fmt.Printf("\n  %s\n\n", interactionURL)
		fmt.Print("Press Enter once you see the \"Authorization complete\" page in the browser… ")
		bufio.NewReader(os.Stdin).ReadString('\n')
	} else {
		log.Println("\n─── Step 2: browser visits interaction URL (auto-follows OAuth redirects) ───")
		log.Printf("  GET %s", interactionURL)

		jar, err := cookiejar.New(nil)
		if err != nil {
			log.Fatalf("cookiejar: %v", err)
		}
		browserClient := &http.Client{
			Jar: jar, // persist the PKCE cookie across redirects
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				log.Printf("  → redirect %s", req.URL)
				return nil
			},
			Timeout: 15 * time.Second,
		}
		browserResp, err := browserClient.Get(interactionURL)
		if err != nil {
			log.Fatalf("browser GET: %v", err)
		}
		browserResp.Body.Close()
		if browserResp.StatusCode != http.StatusOK {
			log.Fatalf("browser flow ended with status %d (expected 200)", browserResp.StatusCode)
		}
		log.Printf("  browser flow complete (status 200)")
	}

	// ── 6. Step 3: poll /pending/{id} until 200 + AAuth-Access ───────────────
	log.Println("\n─── Step 3: agent polls /pending/{id} ───")
	pendingID := extractPendingID(locationURL)
	if pendingID == "" {
		log.Fatalf("cannot extract pending ID from %q", locationURL)
	}
	pendingPath := "/pending/" + pendingID

	maxPolls := 30
	if *realOAuth {
		maxPolls = 5 // user already pressed Enter; the entry should already be Complete
	}
	var opaqueToken string
	for i := 0; i < maxPolls; i++ {
		pollResp, _, err := signedCheck(client, *resourceID, *authority, pendingPath, agentPubB64, agentPriv, nil)
		if err != nil {
			log.Fatalf("check poll %d: %v", i+1, err)
		}
		denied, isDenied := pollResp.HttpResponse.(*pb.CheckResponse_DeniedResponse)
		if !isDenied {
			log.Fatalf("poll %d: expected DeniedResponse, got OkResponse", i+1)
		}
		d := denied.DeniedResponse
		log.Printf("  poll %d: status=%v body=%s", i+1, d.Status.Code, d.Body)

		switch d.Status.Code {
		case pb.StatusCode_Accepted:
			time.Sleep(500 * time.Millisecond)
			continue
		case pb.StatusCode_OK:
			for _, h := range d.Headers {
				if strings.EqualFold(h.Header.Key, "aauth-access") {
					opaqueToken = h.Header.Value
				}
			}
			if opaqueToken == "" {
				log.Fatalf("poll got 200 but no AAuth-Access header")
			}
			log.Printf("  AAuth-Access: %s...", truncate(opaqueToken, 40))
		default:
			log.Fatalf("poll %d: unexpected status %v", i+1, d.Status.Code)
		}
		break
	}
	if opaqueToken == "" {
		log.Fatalf("timed out waiting for AAuth-Access token")
	}

	// ── 7. Step 4: API call with Authorization: AAuth <opaque> ───────────────
	log.Println("\n─── Step 4: API call with AAuth-Access token ───")
	resp4, sent4, err := signedCheck(client, *resourceID, *authority, *path, agentPubB64, agentPriv,
		map[string]string{"authorization": "AAuth " + opaqueToken})
	if err != nil {
		log.Fatalf("check step4: %v", err)
	}
	printAndCheckResourceRequestHeaders(*authority, *path, sent4)
	okResp, isOK := resp4.HttpResponse.(*pb.CheckResponse_OkResponse)
	if !isOK {
		printResponse("step4", resp4)
		log.Fatalf("expected OkResponse (allow), got DeniedResponse")
	}
	var injectedBearer string
	for _, h := range okResp.OkResponse.Headers {
		log.Printf("  upstream header: %s: %s", h.Header.Key, h.Header.Value)
		if strings.EqualFold(h.Header.Key, "authorization") {
			injectedBearer = h.Header.Value
		}
	}
	if !strings.HasPrefix(strings.ToLower(injectedBearer), "bearer ") {
		log.Fatalf("FAIL: expected Authorization: Bearer ... in OkResponse, got %q", injectedBearer)
	}
	injectedToken := injectedBearer[len("Bearer "):]
	if *realOAuth {
		// We don't know what the real provider issued, but verify it looks like a token
		// (non-empty, not the obvious empty/error placeholder).
		if injectedToken == "" {
			log.Fatalf("FAIL: empty Bearer token injected")
		}
		log.Printf("\n✓ PASS: injected Authorization: Bearer %s (real OAuth token, %d chars)",
			truncate(injectedToken, 20), len(injectedToken))
		log.Printf("  Try it against the provider:")
		log.Printf("    curl -H 'Authorization: Bearer %s' https://api.github.com/user", injectedToken)
	} else {
		if injectedToken != stubToken {
			log.Fatalf("FAIL: injected token %q != stub token %q", injectedToken, stubToken)
		}
		log.Printf("\n✓ PASS: injected Authorization: Bearer %s (matches stub token)", injectedToken)
	}

	// ── Step 4b (optional): prove the path through agentgateway → backend works ──
	if *viaAgw != "" {
		log.Println("\n─── Step 4b: same call routed through agentgateway → httpbin ───")
		log.Printf("  GET %s/headers (signed; Authorization: AAuth …)", *viaAgw)
		if err := callViaAgentgateway(*viaAgw, "/headers", *authority, agentPubB64, agentPriv, opaqueToken); err != nil {
			log.Fatalf("via-agw call: %v", err)
		}
	}

	// ── 8. Step 5: NEGATIVE — different agent key cannot use Agent A's token ─────
	log.Println("\n─── Step 5: negative test — different agent key reusing the token ───")
	_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("gen other key: %v", err)
	}
	otherPub := otherPriv.Public().(ed25519.PublicKey)
	otherPubB64 := base64.RawURLEncoding.EncodeToString(otherPub)

	resp5, _, err := signedCheck(client, *resourceID, *authority, *path, otherPubB64, otherPriv,
		map[string]string{"authorization": "AAuth " + opaqueToken})
	if err != nil {
		log.Fatalf("check step5: %v", err)
	}
	if _, isOK := resp5.HttpResponse.(*pb.CheckResponse_OkResponse); isOK {
		log.Fatal("FAIL: different agent key was ALLOWED to use the AAuth-Access token")
	}
	deniedB, _ := resp5.HttpResponse.(*pb.CheckResponse_DeniedResponse)
	log.Printf("  ✓ different agent correctly DENIED (status=%v body=%s)",
		deniedB.DeniedResponse.Status.Code, deniedB.DeniedResponse.Body)

	log.Println("\n✓ Mode 2 integration test PASSED (positive + negative)")
}

// ── Stub OAuth server ─────────────────────────────────────────────────────────

type stubOAuthServer struct {
	accessToken string
	mux         *http.ServeMux
}

func newStubOAuthServer(accessToken string) *stubOAuthServer {
	s := &stubOAuthServer{accessToken: accessToken}
	s.mux = http.NewServeMux()
	s.mux.HandleFunc("/oauth/authorize", s.authorize)
	s.mux.HandleFunc("/oauth/token", s.token)
	return s
}

func (s *stubOAuthServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *stubOAuthServer) authorize(w http.ResponseWriter, r *http.Request) {
	redirectURI := r.URL.Query().Get("redirect_uri")
	state := r.URL.Query().Get("state")
	code := "stub-code-" + randomHex(8)
	log.Printf("[stub] /authorize state=%s → code=%s", state, code)
	target := redirectURI + "?code=" + url.QueryEscape(code) + "&state=" + url.QueryEscape(state)
	http.Redirect(w, r, target, http.StatusFound)
}

func (s *stubOAuthServer) token(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	log.Printf("[stub] /token code=%s", r.FormValue("code"))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token": s.accessToken,
		"token_type":   "bearer",
		"scope":        "read:user",
	})
}

// ── Spec-compliance printing for the resource-managed access request ─────────

// printAndCheckResourceRequestHeaders prints the headers being sent to the resource
// when the agent presents an AAuth-Access token, formatted to mirror the spec example
// in draft-hardt-oauth-aauth-protocol §704 (AAuth-Access Response Header), and asserts
// the two MUST-level requirements:
//
//   - Authorization MUST be "AAuth <opaque>"                          (§704)
//   - Signature-Input MUST cover the "authorization" component        (§704, §2441)
//
// The actual server-side enforcement of the second rule lives in
// internal/extauthz/aauth_mode2.go (authorizationIsCoveredBySig); this print is for
// the operator's eyes — to see exactly what the wire looks like and confirm compliance.
func printAndCheckResourceRequestHeaders(authority, path string, sent map[string]string) {
	log.Println("  outgoing request to the resource (spec §704):")
	log.Printf("    GET %s HTTP/1.1", path)
	log.Printf("    Host: %s", authority)
	log.Printf("    Authorization:   %s", truncateMiddle(sent["authorization"], 70))
	log.Printf("    Signature-Key:   %s", truncateMiddle(sent["signature-key"], 80))
	log.Printf("    Signature-Input: %s", sent["signature-input"])
	log.Printf("    Signature:       %s", truncateMiddle(sent["signature"], 70))

	// Assertion 1: Authorization scheme is AAuth (case-insensitive per HTTP).
	authVal := sent["authorization"]
	if !strings.HasPrefix(strings.ToLower(authVal), "aauth ") {
		log.Fatalf("  ✗ SPEC VIOLATION: Authorization MUST start with \"AAuth \" (got %q)", authVal)
	}
	log.Println("    ✓ Authorization scheme = AAuth (spec §704)")

	// Assertion 2: authorization is in the signed components.
	sigIn := sent["signature-input"]
	if !strings.Contains(sigIn, `"authorization"`) {
		log.Fatalf("  ✗ SPEC VIOLATION: Signature-Input MUST cover \"authorization\" component\n     got: %s", sigIn)
	}
	log.Println("    ✓ Signature-Input covers \"authorization\" (spec §704, §2441 — binds the opaque token to the signature)")
}

// truncateMiddle shortens a long string by replacing the middle with "…" so both
// ends remain visible (good for showing structure of base64 blobs and JWTs).
func truncateMiddle(s string, max int) string {
	if len(s) <= max {
		return s
	}
	half := (max - 1) / 2
	return s[:half] + "…" + s[len(s)-half:]
}

// ── HTTP-through-agentgateway ─────────────────────────────────────────────────

// callViaAgentgateway makes a signed HTTP GET to agwBase+path with
// Authorization: AAuth <opaque> covered by the signature. This is what an agent does
// in production: hit the agentgateway URL, agentgateway calls ExtAuthZ (which unwraps),
// the request is forwarded to the upstream with Authorization: Bearer injected.
//
// We hit httpbin's /headers (the default backend in demo/agw-config-mode2.yaml) which
// echoes back what it received, so we can VISUALLY confirm Authorization: Bearer is in
// the upstream-received headers.
func callViaAgentgateway(agwBase, path, authority, agentPubB64 string, priv ed25519.PrivateKey, opaque string) error {
	components := []string{"@method", "@authority", "@path", "signature-key", "authorization"}
	sigKeyVal := `sig=hwk;kty="OKP";crv="Ed25519";x="` + agentPubB64 + `"`
	authHdr := "AAuth " + opaque

	allHeaders := map[string][]string{
		"signature-key": {sigKeyVal},
		"authorization": {authHdr},
	}
	signInput := httpsig.SignInput{
		Method:     http.MethodGet,
		Authority:  authority,
		Path:       path,
		Headers:    allHeaders,
		Label:      "sig",
		Components: components,
		Params: structfields.Params{
			{Name: "created", Value: time.Now().Unix()},
			{Name: "alg", Value: "ed25519"},
		},
		PrivateKey: priv,
		Alg:        "ed25519",
	}
	sigBytes, sigInputStr, err := httpsig.Sign(signInput)
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}

	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(agwBase, "/")+path, nil)
	if err != nil {
		return err
	}
	req.Host = authority
	req.Header.Set("signature-key", sigKeyVal)
	req.Header.Set("signature-input", sigInputStr)
	req.Header.Set("signature", "sig=:"+base64.StdEncoding.EncodeToString(sigBytes)+":")
	req.Header.Set("authorization", authHdr)

	// Spec-compliance check on the wire we're about to send.
	printAndCheckResourceRequestHeaders(authority, path, map[string]string{
		"authorization":   authHdr,
		"signature-key":   sigKeyVal,
		"signature-input": sigInputStr,
		"signature":       "sig=:" + base64.StdEncoding.EncodeToString(sigBytes) + ":",
	})

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	log.Printf("  response status: %d", resp.StatusCode)
	if resp.StatusCode != http.StatusOK {
		log.Printf("  response body: %s", body)
		return fmt.Errorf("expected 200, got %d", resp.StatusCode)
	}
	log.Printf("  ✓ agentgateway → ExtAuthZ → upstream path verified (got 200)")
	// If the upstream echoes the request headers (e.g. httpbin /headers), surface the
	// injected Bearer for visual confirmation. With a non-echo upstream (e.g. real
	// GitHub /user), the 200 alone is the signal — print the body excerpt instead.
	if i := strings.Index(string(body), `"Authorization": "Bearer `); i >= 0 {
		end := i + 120
		if end > len(body) {
			end = len(body)
		}
		log.Printf("  upstream echoed Bearer: %s…", body[i:end])
	} else {
		excerpt := string(body)
		if len(excerpt) > 200 {
			excerpt = excerpt[:200] + "…"
		}
		log.Printf("  upstream body excerpt: %s", excerpt)
	}
	return nil
}

// ── Signing ───────────────────────────────────────────────────────────────────

// signedCheck builds a signed gRPC CheckRequest using the hwk (bare public key) scheme.
// This matches the simpler pattern of cmd/integration-test/main.go — no stub agent server needed.
// Returns the response AND the flat header map that was sent (so callers can print or inspect).
func signedCheck(
	client pb.AuthorizationClient,
	resourceID, authority, path, agentPubB64 string,
	priv ed25519.PrivateKey,
	extraHeaders map[string]string,
) (*pb.CheckResponse, map[string]string, error) {
	components := []string{"@method", "@authority", "@path", "signature-key"}
	allHeaders := map[string][]string{}

	for k, v := range extraHeaders {
		low := strings.ToLower(k)
		allHeaders[low] = []string{v}
		components = append(components, low)
	}

	sigKeyVal := `sig=hwk;kty="OKP";crv="Ed25519";x="` + agentPubB64 + `"`
	allHeaders["signature-key"] = []string{sigKeyVal}

	signInput := httpsig.SignInput{
		Method:     http.MethodGet,
		Authority:  authority,
		Path:       path,
		Headers:    allHeaders,
		Label:      "sig",
		Components: components,
		Params: structfields.Params{
			{Name: "created", Value: time.Now().Unix()},
			{Name: "alg", Value: "ed25519"},
		},
		PrivateKey: priv,
		Alg:        "ed25519",
	}
	sigBytes, sigInputStr, err := httpsig.Sign(signInput)
	if err != nil {
		return nil, nil, fmt.Errorf("sign: %w", err)
	}

	flat := map[string]string{
		"signature-key":   sigKeyVal,
		"signature-input": sigInputStr,
		"signature":       "sig=:" + base64.StdEncoding.EncodeToString(sigBytes) + ":",
	}
	for k, v := range extraHeaders {
		flat[strings.ToLower(k)] = v
	}

	resp, err := client.Check(context.Background(), &pb.CheckRequest{
		Attributes: &pb.AttributeContext{
			ContextExtensions: map[string]string{
				"aauth_resource_id": resourceID,
			},
			Request: &pb.AttributeContext_Request{
				Http: &pb.AttributeContext_HttpRequest{
					Method:  http.MethodGet,
					Host:    authority,
					Path:    path,
					Headers: flat,
				},
			},
		},
	})
	return resp, flat, err
}

// ── Parsing ───────────────────────────────────────────────────────────────────

// parseInteractionChallenge extracts the interaction code and Location polling URL
// from the DeniedHttpResponse headers of a 202 challenge.
func parseInteractionChallenge(headers []*pb.HeaderValueOption) (code, locationURL string) {
	for _, h := range headers {
		switch strings.ToLower(h.Header.Key) {
		case "location":
			locationURL = h.Header.Value
		case "aauth-requirement":
			code = extractCode(h.Header.Value)
		}
	}
	return
}

func extractCode(requirementHeader string) string {
	dict, err := structfields.ParseDictionary(requirementHeader)
	if err != nil {
		log.Printf("parse AAuth-Requirement %q: %v", requirementHeader, err)
		return ""
	}
	v, ok := dict.Get("code")
	if !ok {
		return ""
	}
	if item, ok := v.(structfields.Item); ok {
		if s, ok := item.Value.(string); ok {
			return s
		}
	}
	return ""
}

func extractPendingID(locationURL string) string {
	if locationURL == "" {
		return ""
	}
	parts := strings.Split(strings.TrimRight(locationURL, "/"), "/")
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}

// ── Misc ──────────────────────────────────────────────────────────────────────

func printResponse(label string, resp *pb.CheckResponse) {
	b, _ := json.MarshalIndent(resp, "", "  ")
	log.Printf("%s response:\n%s", label, b)
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

