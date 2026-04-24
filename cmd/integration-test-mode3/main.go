package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "aauth-service/gen/proto"
	"aauth-service/internal/aauth"
	"aauth-service/pkg/httpsig"
	"aauth-service/pkg/httpsig/structfields"
)

func main() {
	mode := flag.String("mode", "drive", "Mode: drive or ps")
	listen := flag.String("listen", "127.0.0.1:9191", "Listen address for ps mode")
	psBase := flag.String("ps", "http://127.0.0.1:9191", "Stub PS base URL for drive mode")
	grpcAddr := flag.String("grpc", "127.0.0.1:17070", "AAuth gRPC address for drive mode")
	resourceIssuer := flag.String("resource-issuer", "http://127.0.0.1:18090", "Resource issuer")
	resourceID := flag.String("resource-id", "mode3-demo", "AAuth resource ID")
	authority := flag.String("authority", "localhost", "Signed request authority")
	path := flag.String("path", "/mode3", "Signed request path")
	resourceJWKS := flag.String("resource-jwks", "", "Resource JWKS URL for ps mode")
	flag.Parse()

	switch *mode {
	case "ps":
		runStubPersonServer(*listen, *resourceJWKS)
	case "drive":
		if err := runDriver(*grpcAddr, *psBase, *resourceIssuer, *resourceID, *authority, *path); err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatalf("unknown mode %q", *mode)
	}
}

type stubPersonServer struct {
	baseURL      string
	resourceJWKS string
	pub          ed25519.PublicKey
	priv         ed25519.PrivateKey
}

func runStubPersonServer(listenAddr, resourceJWKS string) {
	if resourceJWKS == "" {
		log.Fatal("-resource-jwks is required in ps mode")
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	srv := &stubPersonServer{
		baseURL:      "http://" + listenAddr,
		resourceJWKS: resourceJWKS,
		pub:          pub,
		priv:         priv,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/aauth-agent.json", srv.handleMetadata)
	mux.HandleFunc("/.well-known/aauth-access.json", srv.handleMetadata)
	mux.HandleFunc("/.well-known/aauth-person.json", srv.handleMetadata)
	mux.HandleFunc("/.well-known/jwks.json", srv.handleJWKS)
	mux.HandleFunc("/mint-agent", srv.handleMintAgent)
	mux.HandleFunc("/token", srv.handleToken)

	log.Printf("stub PS listening on %s", listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, mux))
}

func (s *stubPersonServer) handleMetadata(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"jwks_uri": s.baseURL + "/.well-known/jwks.json",
	})
}

func (s *stubPersonServer) handleJWKS(w http.ResponseWriter, r *http.Request) {
	key, err := jwk.FromRaw(s.pub)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = key.Set(jwk.KeyIDKey, "stub-ps-key")
	_ = key.Set(jwk.AlgorithmKey, "EdDSA")
	_ = key.Set(jwk.KeyUsageKey, "sig")
	set := jwk.NewSet()
	set.AddKey(key)
	data, err := json.Marshal(set)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func (s *stubPersonServer) handleMintAgent(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Aud    string                 `json:"aud"`
		Sub    string                 `json:"sub"`
		CnfJWK map[string]interface{} `json:"cnf_jwk"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Aud == "" || len(req.CnfJWK) == 0 {
		http.Error(w, "aud and cnf_jwk are required", http.StatusBadRequest)
		return
	}
	if req.Sub == "" {
		req.Sub = "aauth:demo-agent@agents.example.com"
	}

	token, err := signJWT("aa-agent+jwt", "stub-ps-key", map[string]interface{}{
		"iss": s.baseURL,
		"dwk": "aauth-agent.json",
		"sub": req.Sub,
		"aud": req.Aud,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"cnf": map[string]interface{}{"jwk": req.CnfJWK},
	}, s.priv)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}

func (s *stubPersonServer) handleToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ResourceToken string                 `json:"resource_token"`
		CnfJWK        map[string]interface{} `json:"cnf_jwk"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.ResourceToken == "" || len(req.CnfJWK) == 0 {
		http.Error(w, "resource_token and cnf_jwk are required", http.StatusBadRequest)
		return
	}

	set, err := fetchJWKS(s.resourceJWKS)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	claims, err := aauth.ParseAndVerifyResourceToken(req.ResourceToken, set, s.baseURL, true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	thumbprint, err := jwkThumbprint(req.CnfJWK)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if thumbprint != claims.AgentJKT {
		http.Error(w, "cnf_jwk thumbprint does not match agent_jkt", http.StatusUnauthorized)
		return
	}

	token, err := signJWT("aa-auth+jwt", "stub-ps-key", map[string]interface{}{
		"iss":   s.baseURL,
		"dwk":   "aauth-access.json",
		"sub":   claims.Agent,
		"aud":   claims.Iss,
		"agent": "https://agents.example.com",
		"scope": claims.Scope,
		"txn":   claims.Txn,
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
		"act":   map[string]interface{}{"sub": thumbprint},
		"cnf":   map[string]interface{}{"jwk": req.CnfJWK},
	}, s.priv)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"access_token": token})
}

func runDriver(grpcAddr, psBase, resourceIssuer, resourceID, authority, path string) error {
	agentPub, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	cnfJWK, err := publicJWKMap(agentPub)
	if err != nil {
		return err
	}

	agentToken, err := mintAgentToken(psBase, resourceIssuer, cnfJWK)
	if err != nil {
		return fmt.Errorf("mint agent token: %w", err)
	}

	conn, err := grpc.Dial(grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	defer conn.Close()
	client := pb.NewAuthorizationClient(conn)

	fmt.Println("Call 1: aa-agent+jwt -> expect 401 challenge")
	resp1, err := signedCheck(client, resourceID, authority, path, agentToken, agentPriv)
	if err != nil {
		return err
	}
	if resp1.GetStatus().GetCode() != 16 {
		return fmt.Errorf("call 1 expected UNAUTHENTICATED, got %d", resp1.GetStatus().GetCode())
	}
	resourceToken, err := extractResourceToken(resp1)
	if err != nil {
		return err
	}
	fmt.Println("  received resource-token challenge")

	accessToken, err := exchangeResourceToken(psBase, resourceToken, cnfJWK)
	if err != nil {
		return fmt.Errorf("exchange resource token: %w", err)
	}

	fmt.Println("Call 2: aa-auth+jwt -> expect 200 OK")
	resp2, err := signedCheck(client, resourceID, authority, path, accessToken, agentPriv)
	if err != nil {
		return err
	}
	if resp2.GetStatus().GetCode() != 0 {
		return fmt.Errorf("call 2 expected OK, got %d", resp2.GetStatus().GetCode())
	}
	okResp, ok := resp2.HttpResponse.(*pb.CheckResponse_OkResponse)
	if !ok {
		return fmt.Errorf("call 2 missing OK response")
	}
	level := headerValue(okResp.OkResponse.Headers, "x-aauth-level")
	if level != "authorized" {
		return fmt.Errorf("call 2 expected x-aauth-level=authorized, got %q", level)
	}
	fmt.Println("  authorized")
	return nil
}

func signedCheck(client pb.AuthorizationClient, resourceID, authority, path, jwt string, signer ed25519.PrivateKey) (*pb.CheckResponse, error) {
	sigKeyVal := `sig=jwt;jwt="` + jwt + `"`
	headers := map[string][]string{
		"signature-key": {sigKeyVal},
	}
	signInput := httpsig.SignInput{
		Method:     http.MethodGet,
		Authority:  authority,
		Path:       path,
		Headers:    headers,
		Label:      "sig",
		Components: []string{"@method", "@authority", "@path", "signature-key"},
		Params: structfields.Params{
			{Name: "created", Value: time.Now().Unix()},
			{Name: "alg", Value: "ed25519"},
		},
		PrivateKey: signer,
		Alg:        "ed25519",
	}
	sigBytes, sigInputStr, err := httpsig.Sign(signInput)
	if err != nil {
		return nil, err
	}

	return client.Check(context.Background(), &pb.CheckRequest{
		Attributes: &pb.AttributeContext{
			ContextExtensions: map[string]string{
				"aauth_resource_id": resourceID,
			},
			Request: &pb.AttributeContext_Request{
				Http: &pb.AttributeContext_HttpRequest{
					Method: http.MethodGet,
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
	})
}

func extractResourceToken(resp *pb.CheckResponse) (string, error) {
	denied, ok := resp.HttpResponse.(*pb.CheckResponse_DeniedResponse)
	if !ok {
		return "", fmt.Errorf("expected denied response")
	}
	for _, h := range denied.DeniedResponse.Headers {
		if strings.EqualFold(h.Header.Key, "AAuth-Requirement") {
			dict, err := structfields.ParseDictionary(h.Header.Value)
			if err != nil {
				return "", err
			}
			item, ok := dict.Get("resource-token")
			if !ok {
				return "", fmt.Errorf("resource-token missing from challenge")
			}
			token, ok := item.(structfields.Item).Value.(string)
			if !ok || token == "" {
				return "", fmt.Errorf("resource-token malformed")
			}
			return token, nil
		}
	}
	return "", fmt.Errorf("AAuth-Requirement header missing")
}

func mintAgentToken(psBase, aud string, cnfJWK map[string]interface{}) (string, error) {
	var resp struct {
		Token string `json:"token"`
	}
	err := postJSON(psBase+"/mint-agent", map[string]interface{}{
		"aud":     aud,
		"sub":     "aauth:demo-agent@agents.example.com",
		"cnf_jwk": cnfJWK,
	}, &resp)
	return resp.Token, err
}

func exchangeResourceToken(psBase, resourceToken string, cnfJWK map[string]interface{}) (string, error) {
	var resp struct {
		AccessToken string `json:"access_token"`
	}
	err := postJSON(psBase+"/token", map[string]interface{}{
		"resource_token": resourceToken,
		"cnf_jwk":        cnfJWK,
	}, &resp)
	return resp.AccessToken, err
}

func postJSON(url string, reqBody any, respBody any) error {
	data, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	if respBody == nil {
		return nil
	}
	return json.Unmarshal(body, respBody)
}

func fetchJWKS(url string) (jwk.Set, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return jwk.ParseReader(resp.Body)
}

func signJWT(typ, kid string, claims map[string]interface{}, signer ed25519.PrivateKey) (string, error) {
	headerBytes, err := json.Marshal(map[string]interface{}{
		"typ": typ,
		"alg": "EdDSA",
		"kid": kid,
	})
	if err != nil {
		return "", err
	}
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	unsigned := base64.RawURLEncoding.EncodeToString(headerBytes) + "." + base64.RawURLEncoding.EncodeToString(claimsBytes)
	sig := ed25519.Sign(signer, []byte(unsigned))
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func publicJWKMap(pub ed25519.PublicKey) (map[string]interface{}, error) {
	key, err := jwk.FromRaw(pub)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(key)
	if err != nil {
		return nil, err
	}
	var out map[string]interface{}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func jwkThumbprint(jwkMap map[string]interface{}) (string, error) {
	b, err := json.Marshal(jwkMap)
	if err != nil {
		return "", err
	}
	key, err := jwk.ParseKey(b)
	if err != nil {
		return "", err
	}
	tp, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(tp), nil
}

func headerValue(headers []*pb.HeaderValueOption, key string) string {
	for _, h := range headers {
		if strings.EqualFold(h.Header.Key, key) {
			return h.Header.Value
		}
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
