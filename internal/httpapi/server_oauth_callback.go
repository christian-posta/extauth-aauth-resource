package httpapi

import (
	"log"
	"net/http"
	"time"

	"aauth-service/internal/oauthbridge"
	"aauth-service/internal/wrappedtoken"
)

// handleOAuthCallback handles GET /oauth/{rid}/callback?code=...&state=...
// This is the redirect_uri that the upstream OAuth provider sends the user back to.
// It exchanges the authorization code for OAuth tokens, wraps them in an opaque blob,
// and marks the pending entry complete so the agent's next poll returns AAuth-Access.
func (s *Server) handleOAuthCallback(w http.ResponseWriter, r *http.Request, rid string) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	errParam := r.URL.Query().Get("error")
	if errParam != "" {
		errDesc := r.URL.Query().Get("error_description")
		log.Printf("oauth_callback: provider error resource=%s error=%s desc=%s", rid, errParam, errDesc)
		showErrorPage(w, "Authorization failed: "+errParam)
		return
	}

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		http.Error(w, "Missing code or state", http.StatusBadRequest)
		return
	}

	rc, ok := s.registry.ByID(rid)
	if !ok || rc.OAuthBridge == nil {
		log.Printf("oauth_callback: resource %s not found or has no oauth_bridge", rid)
		http.Error(w, "Unknown resource", http.StatusBadRequest)
		return
	}

	// Look up the pending entry by OAuthState (CSRF validation).
	e := s.mode2.PendingStore.ByOAuthState(state)
	if e == nil {
		log.Printf("oauth_callback: unknown oauth state resource=%s state=%s", rid, state)
		showErrorPage(w, "Invalid state parameter — possible CSRF attack or expired session")
		return
	}

	if e.ResourceID != rid {
		log.Printf("oauth_callback: state/resource mismatch pending=%s state_resource=%s url_resource=%s", e.ID, e.ResourceID, rid)
		showErrorPage(w, "Resource mismatch")
		return
	}

	// Retrieve PKCE verifier from cookie if PKCE is enabled.
	var pkceVerifier string
	if rc.OAuthBridge.UsePKCE {
		c, err := r.Cookie("pkce_" + e.ID)
		if err != nil || c.Value == "" {
			log.Printf("oauth_callback: missing PKCE cookie for pending entry %s", e.ID)
			showErrorPage(w, "Missing PKCE verifier")
			return
		}
		pkceVerifier = c.Value
		// Clear the cookie.
		http.SetCookie(w, &http.Cookie{
			Name:   "pkce_" + e.ID,
			Value:  "",
			MaxAge: -1,
		})
	}

	// Exchange the authorization code for tokens.
	result, err := oauthbridge.ExchangeCode(r.Context(), rc, code, pkceVerifier)
	if err != nil {
		log.Printf("oauth_callback: code exchange failed resource=%s: %v", rid, err)
		s.mode2.PendingStore.Fail(e.ID, err.Error())
		showErrorPage(w, "Token exchange failed")
		return
	}

	// Wrap the token into an opaque AAuth-Access blob.
	key, ok := s.mode2.TokenKeys.ForResource(rid)
	if !ok {
		log.Printf("oauth_callback: no opaque token key for resource %s", rid)
		s.mode2.PendingStore.Fail(e.ID, "misconfigured resource key")
		showErrorPage(w, "Server configuration error")
		return
	}

	tok := wrappedtoken.Token{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		TokenType:    result.TokenType,
		ExpiresAt:    result.ExpiresAt,
		Scope:        result.Scope,
		AgentJKT:     e.AgentJKT, // bind to the originating agent's key thumbprint
		IssuedAt:     time.Now(),
	}
	opaque, err := wrappedtoken.Wrap(tok, rid, key)
	if err != nil {
		log.Printf("oauth_callback: wrap token resource=%s: %v", rid, err)
		s.mode2.PendingStore.Fail(e.ID, "token wrap error")
		showErrorPage(w, "Internal error")
		return
	}

	if err := s.mode2.PendingStore.Complete(e.ID, opaque); err != nil {
		log.Printf("oauth_callback: complete pending entry %s: %v", e.ID, err)
		showErrorPage(w, "Internal error completing authorization")
		return
	}

	log.Printf("oauth_callback: authorization complete resource=%s agent=%s", rid, e.AgentID)

	if rc.SuccessRedirect != "" {
		http.Redirect(w, r, rc.SuccessRedirect, http.StatusFound)
		return
	}
	showSuccessPage(w)
}

func showSuccessPage(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`<!DOCTYPE html>
<html>
<head><title>Authorization Complete</title></head>
<body>
<h2>Authorization complete</h2>
<p>You may close this window and return to your agent.</p>
</body>
</html>`))
}

func showErrorPage(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	w.Write([]byte(`<!DOCTYPE html>
<html>
<head><title>Authorization Error</title></head>
<body>
<h2>Authorization error</h2>
<p>` + msg + `</p>
</body>
</html>`))
}

