package httpapi

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	pb "aauth-service/gen/proto"
	"aauth-service/internal/aauth"
	"aauth-service/internal/config"
	"aauth-service/internal/logging"
	"aauth-service/internal/policy"
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
		if res.Diagnostics != nil {
			log.Printf("resource_token verify failed resource=%s method=%s host=%s path=%s scheme=%s stage=%s error=%s detail=%q",
				rc.ID, r.Method, r.Host, path, res.Diagnostics.Scheme, res.Diagnostics.Stage, res.Err.Error(), res.Diagnostics.Detail)
		} else {
			log.Printf("resource_token verify failed resource=%s method=%s host=%s path=%s error=%s",
				rc.ID, r.Method, r.Host, path, res.Err.Error())
		}
		log.Printf("resource_token failure headers resource=%s method=%s host=%s path=%s snapshot=%s",
			rc.ID, r.Method, r.Host, path, logging.FormatRelevantHeaders(lowerHeaders))
		s.writeChallenge(w, rc, res.Err, res.Identity)
		return
	}

	// 3. Body parsing
	var reqBody struct {
		Scope string `json:"scope"`
	}

	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	if strings.TrimSpace(reqBody.Scope) == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "invalid_request",
		})
		return
	}

	aud := aauth.ResolveResourceTokenAud(rc)
	if aud == "" && rc.Access.Require == "auth-token" {
		http.Error(w, "Resource missing person server issuer", http.StatusInternalServerError)
		return
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

	// Mint token. MintResourceToken sets dwk, iat, and jti automatically.
	claims := aauth.ResourceTokenClaims{
		Iss:      rc.Issuer,
		Aud:      aud,
		AgentJKT: res.Identity.JKT,
		Exp:      time.Now().Add(5 * time.Minute).Unix(),
		Scope:    reqBody.Scope,
	}

	if res.Identity.Level == aauth.LevelIdentified || res.Identity.Level == aauth.LevelAuthorized {
		// agent claim = the agent's identifier (sub), not the server URL.
		claims.Agent = res.Identity.Delegate
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
			AgentIdentifier: identity.Delegate,
			AgentJKT:        identity.JKT,
			Scope:           identity.Scope,
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
