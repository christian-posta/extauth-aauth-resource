package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	pb "policy_engine/gen/proto"
	"policy_engine/internal/aauth"
	"policy_engine/internal/config"
	"policy_engine/internal/policy"
)

func (s *Server) handleResourceToken(w http.ResponseWriter, r *http.Request, rc *config.ResourceConfig) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Convert HTTP headers
	headers := make(map[string][]string)
	for k, v := range r.Header {
		headers[k] = v
	}

	// 2. Call AAuth verify
	// Use r.Host to match ExtAuthZ behavior which uses authority
	path := r.URL.Path
	if r.URL.RawQuery != "" {
		path += "?" + r.URL.RawQuery
	}

	// Pre-process headers to be lower-case to match how ExtAuthZ does it
	lowerHeaders := make(map[string][]string)
	for k, v := range headers {
		lowerHeaders[strings.ToLower(k)] = v
	}

	res := aauth.Verify(rc, r.Method, r.Host, path, lowerHeaders, s.jwksClient)
	if res.Err != nil {
		s.writeChallenge(w, rc, res.Err, res.Identity)
		return
	}

	// 3. Body parsing
	var reqBody struct {
		Scope string `json:"scope"`
		Aud   string `json:"aud"`
	}

	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	// Default aud if missing
	if reqBody.Aud == "" {
		if len(rc.AuthServers) > 0 {
			reqBody.Aud = rc.AuthServers[0].Issuer
		} else {
			reqBody.Aud = rc.AuthorizationEndpoint
		}
	}

	// Policy Check
	pIn := policy.PolicyInput{
		Resource: rc.Issuer,
		Method:   r.Method,
		Path:     path,
		Host:     r.Host,
		Identity: res.Identity,
		Headers:  make(map[string]string), // Simplified for Phase 5 HTTP
	}

	decision, err := s.policyEngine.Decide(r.Context(), pIn)
	if err != nil || !decision.Allow {
		// Deny
		s.writeChallenge(w, rc, aauth.ErrInsufficientScope, res.Identity)
		return
	}

	// Mint token
	claims := aauth.ResourceTokenClaims{
		Iss:      rc.Issuer,
		Aud:      reqBody.Aud,
		AgentJKT: res.Identity.JKT,
		Exp:      time.Now().Add(5 * time.Minute).Unix(),
		Scope:    reqBody.Scope,
		Jti:      "TODO-UUID", // Should generate real UUID
	}

	if res.Identity.Level == aauth.LevelIdentified || res.Identity.Level == aauth.LevelAuthorized {
		claims.Agent = res.Identity.AgentServer
	}

	if rc.PrivateKey == nil {
		http.Error(w, "Resource missing private key", http.StatusInternalServerError)
		return
	}

	tokenStr, err := aauth.MintResourceToken(rc, claims, rc.PrivateKey)
	if err != nil {
		http.Error(w, "Failed to mint token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"resource_token": tokenStr,
	})
}

func (s *Server) writeChallenge(w http.ResponseWriter, rc *config.ResourceConfig, authErr error, identity aauth.Identity) {
	var hint *aauth.AgentHint
	if identity.Level != "" {
		hint = &aauth.AgentHint{
			Agent:    identity.AgentServer,
			AgentJKT: identity.JKT,
			Scope:    identity.Scope,
		}
	}

	issueToken := (hint != nil && hint.AgentJKT != "")
	challenge := aauth.NewChallenge(rc, authErr, hint, issueToken)
	resp := challenge.Response()

	denied := resp.HttpResponse.(*pb.CheckResponse_DeniedResponse).DeniedResponse

	for _, hdr := range denied.Headers {
		w.Header().Add(hdr.Header.Key, hdr.Header.Value)
	}

	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte(denied.Body))
}
