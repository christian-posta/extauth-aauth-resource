package httpapi

import (
	"log"
	"net/http"

	"aauth-service/internal/oauthbridge"
	"aauth-service/internal/pending"
)

// handleInteraction handles GET /interaction?code={code}
// This is where the user's browser arrives after the agent provides the interaction URL.
// It validates the single-use code, marks the pending entry as interacting,
// and redirects the user to the upstream OAuth provider's authorization page.
func (s *Server) handleInteraction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Missing interaction code", http.StatusBadRequest)
		return
	}

	e, ok := s.mode2.PendingStore.ByCode(code)
	if !ok {
		http.Error(w, "Invalid or expired interaction code", http.StatusGone)
		return
	}

	if e.State != pending.StatePending {
		http.Error(w, "Interaction code already used", http.StatusGone)
		return
	}

	// Look up the resource to get the OAuth bridge config.
	rc, ok := s.registry.ByID(e.ResourceID)
	if !ok || rc.OAuthBridge == nil {
		log.Printf("interaction: resource %s not found or has no oauth_bridge", e.ResourceID)
		http.Error(w, "Resource misconfigured", http.StatusInternalServerError)
		return
	}

	// Mark interacting — code is now consumed. Even if the OAuth flow fails,
	// the code will not be reusable (spec §904).
	if err := s.mode2.PendingStore.MarkInteracting(e.ID); err != nil {
		log.Printf("interaction: mark interacting %s: %v", e.ID, err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Generate PKCE if enabled; persist verifier on the pending entry by re-creating
	// with the verifier. In practice we store it in-band via Complete.
	// We pass the verifier through the state parameter via OAuthState (already set).
	// For PKCE: store verifier by updating the entry — our simple store doesn't have
	// an UpdatePKCEVerifier method, so we use the state cookie pattern: store in
	// a short-lived cookie keyed by the pending ID.
	var pkceChallenge string
	if rc.OAuthBridge.UsePKCE {
		verifier, challenge := oauthbridge.NewPKCEPair()
		pkceChallenge = challenge
		// Store the verifier in a secure cookie so the callback can retrieve it.
		http.SetCookie(w, &http.Cookie{
			Name:     "pkce_" + e.ID,
			Value:    verifier,
			Path:     "/oauth/" + rc.ID + "/callback",
			MaxAge:   900, // 15 min
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
	}

	authorizeURL := oauthbridge.AuthorizeURL(rc, e.OAuthState, pkceChallenge)
	http.Redirect(w, r, authorizeURL, http.StatusFound)
}
