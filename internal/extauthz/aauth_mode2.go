package extauthz

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/wrapperspb"

	pb "aauth-service/gen/proto"
	"aauth-service/internal/config"
	"aauth-service/internal/pending"
	"aauth-service/internal/wrappedtoken"
	"github.com/christian-posta/aauth-go-library/pkg/aauth"
	"github.com/christian-posta/aauth-go-library/pkg/httpsig/structfields"
)

var pendingPathRE = regexp.MustCompile(`^/pending/([^/]+)$`)

// Mode2Deps holds the shared state needed for the resource-managed (Mode 2) flow.
// It is created once in main and injected into both the gRPC and HTTP layers.
type Mode2Deps struct {
	PendingStore pending.Store
	TokenKeys    *wrappedtoken.Registry
}

// handleInteractionChallenge is the first touch-point for Mode 2.
// The agent has a valid identity but no AAuth-Access token yet and the path
// is not a /pending/ poll. We create a pending entry and return 202.
func handleInteractionChallenge(
	rc *config.ResourceConfig,
	res aauth.VerifyResult,
	deps *Mode2Deps,
) *pb.CheckResponse {
	code := pending.GenerateCode()
	e := &pending.Entry{
		Code:       code,
		ResourceID: rc.ID,
		AgentID:    res.Identity.Delegate,
		AgentJKT:   res.Identity.JKT,
		Scope:      res.Identity.Scope,
	}
	if err := deps.PendingStore.Create(e); err != nil {
		log.Printf("mode2: create pending entry: %v", err)
		return internalErrorResponse("failed to create pending entry")
	}

	interactionURL := interactionURLForResource(rc)
	pendingURL := pendingURLForResource(rc, e.ID)
	return buildInteractionResponse(e, interactionURL, pendingURL, false)
}

// handlePendingPoll handles the agent polling /pending/{id}.
func handlePendingPoll(
	rc *config.ResourceConfig,
	res aauth.VerifyResult,
	id string,
	deps *Mode2Deps,
) *pb.CheckResponse {
	// Verify that the polling agent is the same one that initiated the request.
	e, ok := deps.PendingStore.ByID(id)
	if !ok {
		return terminalResponse(http.StatusGone, `{"error":"not_found","status":"gone"}`)
	}

	// Bind: only the originating agent may poll.
	if res.Identity.JKT != e.AgentJKT {
		log.Printf("mode2: poll agent JKT mismatch: got %s want %s", res.Identity.JKT, e.AgentJKT)
		return terminalResponse(http.StatusForbidden, `{"error":"forbidden"}`)
	}

	interactionURL := interactionURLForResource(rc)
	pendingURL := pendingURLForResource(rc, e.ID)

	switch e.State {
	case pending.StatePending:
		return buildInteractionResponse(e, interactionURL, pendingURL, false)

	case pending.StateInteracting:
		return buildInteractionResponse(e, interactionURL, pendingURL, true)

	case pending.StateComplete:
		// Consume the entry — subsequent polls return 410.
		consumed, err := deps.PendingStore.Consume(id)
		if err != nil {
			log.Printf("mode2: consume pending entry %s: %v", id, err)
			return internalErrorResponse("failed to consume pending entry")
		}
		// Return 200 with AAuth-Access header.
		return buildAccessGrantedResponse(consumed.OpaqueToken)

	case pending.StateConsumed:
		return terminalResponse(http.StatusGone, `{"error":"gone","status":"consumed"}`)

	case pending.StateFailed:
		body, _ := json.Marshal(map[string]string{
			"error":  "interaction_failed",
			"detail": e.LastErr,
		})
		return terminalResponse(http.StatusForbidden, string(body))

	default:
		return terminalResponse(http.StatusGone, `{"error":"gone"}`)
	}
}

// handleAAuthAccess handles requests where the agent presents Authorization: AAuth <opaque>.
// It unwraps the token, verifies the agent-key binding, and returns an OK response
// with Authorization: Bearer <oauth_access_token> injected for the upstream.
func handleAAuthAccess(
	rc *config.ResourceConfig,
	res aauth.VerifyResult,
	headers map[string][]string,
	deps *Mode2Deps,
) *pb.CheckResponse {
	opaque := extractAAuthToken(headers)
	if opaque == "" {
		log.Printf("mode2: empty AAuth token")
		return buildSimpleChallenge(http.StatusUnauthorized, "invalid_token")
	}

	// Verify that "authorization" is a covered component in Signature-Input.
	// Per spec §718: the agent MUST include authorization in signed components.
	if !authorizationIsCoveredBySig(headers) {
		log.Printf("mode2: authorization header not covered by Signature-Input")
		return buildSimpleChallenge(http.StatusUnauthorized, "invalid_signature")
	}

	key, ok := deps.TokenKeys.ForResource(rc.ID)
	if !ok {
		log.Printf("mode2: no opaque token key for resource %s", rc.ID)
		return internalErrorResponse("misconfigured resource")
	}

	tok, err := wrappedtoken.Unwrap(opaque, rc.ID, key)
	if err != nil {
		log.Printf("mode2: unwrap token for resource %s: %v", rc.ID, err)
		return buildSimpleChallenge(http.StatusUnauthorized, "invalid_token")
	}

	// Verify agent-key binding: the JKT in the wrapped token must match the
	// JKT of the agent that is presenting this request.
	if tok.AgentJKT != res.Identity.JKT {
		log.Printf("mode2: agent JKT binding mismatch resource=%s want=%s got=%s",
			rc.ID, tok.AgentJKT, res.Identity.JKT)
		return buildSimpleChallenge(http.StatusUnauthorized, "invalid_token")
	}

	// Handle token expiry. GitHub classic OAuth tokens never expire (zero ExpiresAt);
	// fine-grained tokens or other providers may have expiry.
	accessToken := tok.AccessToken
	if tok.IsExpired() {
		if tok.RefreshToken == "" {
			log.Printf("mode2: token expired and no refresh token for resource %s", rc.ID)
			return buildSimpleChallenge(http.StatusUnauthorized, "token_expired")
		}
		// Refresh is handled by the HTTP side and produces a new wrapped token.
		// For now: expire the token; the agent will re-run the interaction.
		// See docs/mode2-github.md §"Rolling refresh" for future improvement.
		log.Printf("mode2: token expired for resource %s; agent must re-authorize", rc.ID)
		return buildSimpleChallenge(http.StatusUnauthorized, "token_expired")
	}

	// Proactively refresh if within 5 minutes of expiry (in-place, no header back to agent yet).
	if tok.RefreshToken != "" && tok.ExpiresWithin(5*time.Minute) {
		log.Printf("mode2: token expiring soon for resource %s; would refresh (TODO: emit new AAuth-Access)", rc.ID)
		// TODO: refresh and emit AAuth-Access on response headers.
		// ExtAuthZ OkResponse can only set request headers, not response headers.
		// For now, continue with the current token until it actually expires.
	}

	return buildBearerAllowResponse(rc, res, accessToken)
}

// ─── Response builders ────────────────────────────────────────────────────────

// buildInteractionResponse returns a 202 DeniedHttpResponse with AAuth-Requirement.
// When interacting=true the body says "interacting" so the agent stops re-prompting.
func buildInteractionResponse(e *pending.Entry, interactionURL, pendingURL string, interacting bool) *pb.CheckResponse {
	statusStr := "pending"
	if interacting {
		statusStr = "interacting"
	}

	// AAuth-Requirement: requirement=interaction; url="..."; code="..."
	reqDict := structfields.Dictionary{
		{Name: "requirement", Value: structfields.Item{Value: structfields.Token("interaction")}},
		{Name: "url", Value: structfields.Item{Value: interactionURL}},
		{Name: "code", Value: structfields.Item{Value: e.Code}},
	}
	reqHeader, _ := structfields.SerializeDictionary(reqDict)

	body, _ := json.Marshal(map[string]string{"status": statusStr})

	retryAfter := "0"
	if interacting {
		retryAfter = "3"
	}

	headers := []*pb.HeaderValueOption{
		hv("AAuth-Requirement", reqHeader),
		hv("Location", pendingURL),
		hv("Retry-After", retryAfter),
		hv("Cache-Control", "no-store"),
		hv("Content-Type", "application/json"),
	}

	return &pb.CheckResponse{
		Status: &pb.Status{Code: 16}, // UNAUTHENTICATED
		HttpResponse: &pb.CheckResponse_DeniedResponse{
			DeniedResponse: &pb.DeniedHttpResponse{
				Status:  &pb.HttpStatus{Code: pb.StatusCode_Accepted},
				Headers: headers,
				Body:    string(body),
			},
		},
	}
}

// buildAccessGrantedResponse returns a 200 DeniedHttpResponse with AAuth-Access header.
// Using DeniedHttpResponse here (not OkResponse) ensures agentgateway does NOT forward
// the request to the upstream backend — the agent is just polling, not calling the API.
func buildAccessGrantedResponse(opaqueToken string) *pb.CheckResponse {
	body, _ := json.Marshal(map[string]string{"status": "complete"})
	headers := []*pb.HeaderValueOption{
		hv("AAuth-Access", opaqueToken),
		hv("Cache-Control", "no-store"),
		hv("Content-Type", "application/json"),
	}
	return &pb.CheckResponse{
		Status: &pb.Status{Code: 16},
		HttpResponse: &pb.CheckResponse_DeniedResponse{
			DeniedResponse: &pb.DeniedHttpResponse{
				Status:  &pb.HttpStatus{Code: pb.StatusCode_OK},
				Headers: headers,
				Body:    string(body),
			},
		},
	}
}

// buildBearerAllowResponse returns an OkResponse with Authorization: Bearer injected.
// This is the allow path — agentgateway forwards the request to the upstream backend.
func buildBearerAllowResponse(rc *config.ResourceConfig, res aauth.VerifyResult, accessToken string) *pb.CheckResponse {
	upstreamHeaders := []*pb.HeaderValueOption{
		hv("Authorization", "Bearer "+accessToken),
	}
	// Pass through identity headers (agent-id, etc.) from AAuth verification.
	for _, h := range IdentityHeadersToProto(res.Identity.Headers()) {
		upstreamHeaders = append(upstreamHeaders, h)
	}

	var headersToRemove []string
	if rc.StripSignatureHeaders {
		headersToRemove = []string{"signature", "signature-input", "signature-key"}
	}

	return &pb.CheckResponse{
		Status: &pb.Status{Code: 0}, // OK
		HttpResponse: &pb.CheckResponse_OkResponse{
			OkResponse: &pb.OkHttpResponse{
				Headers:         upstreamHeaders,
				HeadersToRemove: headersToRemove,
			},
		},
	}
}

func terminalResponse(status int, body string) *pb.CheckResponse {
	return &pb.CheckResponse{
		Status: &pb.Status{Code: 16},
		HttpResponse: &pb.CheckResponse_DeniedResponse{
			DeniedResponse: &pb.DeniedHttpResponse{
				Status:  &pb.HttpStatus{Code: pb.StatusCode(status)},
				Headers: []*pb.HeaderValueOption{hv("Content-Type", "application/json")},
				Body:    body,
			},
		},
	}
}

func internalErrorResponse(msg string) *pb.CheckResponse {
	body, _ := json.Marshal(map[string]string{"error": "server_error", "detail": msg})
	return terminalResponse(http.StatusInternalServerError, string(body))
}

func buildSimpleChallenge(status int, errCode string) *pb.CheckResponse {
	body, _ := json.Marshal(map[string]string{"error": errCode})
	return &pb.CheckResponse{
		Status: &pb.Status{Code: 16},
		HttpResponse: &pb.CheckResponse_DeniedResponse{
			DeniedResponse: &pb.DeniedHttpResponse{
				Status:  &pb.HttpStatus{Code: pb.StatusCode(status)},
				Headers: []*pb.HeaderValueOption{hv("Content-Type", "application/json")},
				Body:    string(body),
			},
		},
	}
}

// ─── URL helpers ──────────────────────────────────────────────────────────────

func interactionURLForResource(rc *config.ResourceConfig) string {
	return strings.TrimRight(rc.Issuer, "/") + "/interaction"
}

func pendingURLForResource(rc *config.ResourceConfig, pendingID string) string {
	return fmt.Sprintf("%s/pending/%s", strings.TrimRight(rc.Issuer, "/"), pendingID)
}

// ─── Header helpers ───────────────────────────────────────────────────────────

func hv(key, value string) *pb.HeaderValueOption {
	return &pb.HeaderValueOption{
		Header: &pb.HeaderValue{Key: key, Value: value},
		Append: &wrapperspb.BoolValue{Value: false},
	}
}

// extractAAuthToken returns the opaque value after "AAuth " from the authorization header.
func extractAAuthToken(headers map[string][]string) string {
	for _, v := range headers["authorization"] {
		if strings.HasPrefix(strings.ToLower(v), "aauth ") {
			return strings.TrimSpace(v[len("AAuth "):])
		}
	}
	return ""
}

// authorizationIsCoveredBySig checks whether "authorization" appears in Signature-Input.
// Per AAuth spec §718 the agent MUST cover the authorization header in its signature.
// This is a pragmatic string-contains check; full RFC 8941 parsing is not needed here.
func authorizationIsCoveredBySig(headers map[string][]string) bool {
	for _, v := range headers["signature-input"] {
		if strings.Contains(v, `"authorization"`) {
			return true
		}
	}
	return false
}
