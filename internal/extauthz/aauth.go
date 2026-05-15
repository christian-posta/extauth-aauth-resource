package extauthz

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"

	pb "aauth-service/gen/proto"
	"github.com/christian-posta/aauth-go-library/pkg/aauth"
	"aauth-service/internal/config"
	"aauth-service/internal/logging"
	"aauth-service/internal/metrics"
	"aauth-service/internal/policy"
)

type jwksFetcher interface {
	Get(ctx context.Context, uri string) (jwk.Set, error)
	GetMetadata(ctx context.Context, uri string) (map[string]interface{}, error)
	Invalidate(uri string)
}

type AAuthHandler struct {
	policyEngine policy.Engine
	jwksClient   jwksFetcher
	mode2        *Mode2Deps // nil when no interaction-mode resource is configured
}

func NewAAuthHandler(engine policy.Engine, jwksClient jwksFetcher) *AAuthHandler {
	return &AAuthHandler{
		policyEngine: engine,
		jwksClient:   jwksClient,
	}
}

func NewAAuthHandlerWithMode2(engine policy.Engine, jwksClient jwksFetcher, m2 *Mode2Deps) *AAuthHandler {
	return &AAuthHandler{
		policyEngine: engine,
		jwksClient:   jwksClient,
		mode2:        m2,
	}
}

func (h *AAuthHandler) Check(ctx context.Context, req *pb.CheckRequest, rc *config.ResourceConfig) (*pb.CheckResponse, error) {
	attrs := req.GetAttributes()
	httpReq := attrs.GetRequest().GetHttp()

	method := httpReq.GetMethod()
	authority := AuthorityForSignature(httpReq)
	if rc.AuthorityOverride != "" {
		authority = rc.AuthorityOverride
	}
	path := httpReq.GetPath()

	// Convert ExtAuthZ headers to standard map
	headers := make(map[string][]string)
	for k, v := range httpReq.GetHeaders() {
		headers[k] = []string{v}
	}

	verifyOpts := BuildVerifyOptions(rc)

	start := time.Now()
	res := aauth.Verify(ctx, verifyOpts, method, authority, path, headers, h.jwksClient)

	levelStr := string(res.Identity.Level)
	if levelStr == "" {
		levelStr = "none"
	}

	if res.Err != nil {
		reason := res.Err.Error()
		if res.Diagnostics != nil {
			reason = fmt.Sprintf("%s stage=%s scheme=%s detail=%q", reason, res.Diagnostics.Stage, res.Diagnostics.Scheme, res.Diagnostics.Detail)
		}

		metrics.CheckTotal.WithLabelValues(rc.ID, levelStr, "error").Inc()
		metrics.CheckLatency.WithLabelValues(rc.ID, "error").Observe(time.Since(start).Seconds())

		log.Printf("AAuth verification failed resource=%s method=%s host=%s path=%s level=%s error=%s", rc.ID, method, authority, path, levelStr, reason)
		log.Printf("AAuth failure headers resource=%s method=%s host=%s path=%s snapshot=%s", rc.ID, method, authority, path, logging.FormatRelevantHeaders(headers))
		LogAuthorityResolutionOnFailure(httpReq, authority, rc.AuthorityOverride != "", rc.ID)

		var hint *aauth.AgentHint
		if res.Identity.Level != "" {
			hint = &aauth.AgentHint{
				AgentIdentifier: res.Identity.Delegate,
				AgentJKT:        res.Identity.JKT,
				Scope:           res.Identity.Scope,
			}
		}

		// If identity has a JKT, we can issue a resource-token even if they failed
		issueToken := (hint != nil && hint.AgentJKT != "")

		challenge := aauth.NewChallenge(BuildChallengeOptions(rc), res.Err, hint, issueToken)
		built := challenge.Build()
		resp := ChallengeToCheckResponse(built)

		logging.LogDecision(logging.DecisionLog{
			ResourceID:       rc.ID,
			Level:            levelStr,
			AgentServer:      res.Identity.AgentServer,
			Delegate:         res.Identity.Delegate,
			ResourceTokenJTI: built.ResourceTokenJTI,
			Result:           "error",
			Reason:           reason,
			LatencyMs:        time.Since(start).Milliseconds(),
		})
		return resp, nil
	}

	// ── Mode 2: resource-managed (OAuth bridge) ──────────────────────────────
	if rc.Access.Require == "interaction" && h.mode2 != nil {
		authHdr := headers["authorization"]
		hasAAuthToken := len(authHdr) > 0 && strings.HasPrefix(strings.ToLower(authHdr[0]), "aauth ")

		switch {
		case hasAAuthToken:
			// Agent is calling the real API with a wrapped OAuth token.
			resp := handleAAuthAccess(rc, res, headers, h.mode2)
			metrics.CheckTotal.WithLabelValues(rc.ID, levelStr, "mode2_access").Inc()
			metrics.CheckLatency.WithLabelValues(rc.ID, "mode2_access").Observe(time.Since(start).Seconds())
			return resp, nil

		case pendingPathRE.MatchString(path):
			// Agent is polling /pending/{id}.
			matches := pendingPathRE.FindStringSubmatch(path)
			resp := handlePendingPoll(rc, res, matches[1], h.mode2)
			metrics.CheckTotal.WithLabelValues(rc.ID, levelStr, "mode2_poll").Inc()
			metrics.CheckLatency.WithLabelValues(rc.ID, "mode2_poll").Observe(time.Since(start).Seconds())
			return resp, nil

		default:
			// Initial request: issue a 202 interaction challenge.
			resp := handleInteractionChallenge(rc, res, h.mode2)
			metrics.CheckTotal.WithLabelValues(rc.ID, levelStr, "mode2_challenge").Inc()
			metrics.CheckLatency.WithLabelValues(rc.ID, "mode2_challenge").Observe(time.Since(start).Seconds())
			return resp, nil
		}
	}

	if rc.Access.Require == "auth-token" && res.Identity.Level != aauth.LevelAuthorized {
		hint := &aauth.AgentHint{
			AgentIdentifier: res.Identity.Delegate,
			AgentJKT:        res.Identity.JKT,
			Scope:           res.Identity.Scope,
		}
		challenge := aauth.NewChallenge(BuildChallengeOptions(rc), aauth.ErrInsufficientScope, hint, true)
		built := challenge.Build()

		metrics.CheckTotal.WithLabelValues(rc.ID, levelStr, "challenged").Inc()
		metrics.CheckLatency.WithLabelValues(rc.ID, "challenged").Observe(time.Since(start).Seconds())

		logging.LogDecision(logging.DecisionLog{
			ResourceID:       rc.ID,
			Level:            levelStr,
			AgentServer:      res.Identity.AgentServer,
			Delegate:         res.Identity.Delegate,
			ResourceTokenJTI: built.ResourceTokenJTI,
			Result:           "challenged",
			Reason:           aauth.ErrInsufficientScope.Error(),
			LatencyMs:        time.Since(start).Milliseconds(),
		})

		return ChallengeToCheckResponse(built), nil
	}

	// Policy hook
	pIn := policy.PolicyInput{
		Resource:   rc.Issuer,
		Method:     method,
		Path:       path,
		Host:       authority,
		Identity:   res.Identity,
		Headers:    httpReq.GetHeaders(),
		ContextExt: attrs.GetContextExtensions(),
	}

	decision, err := h.policyEngine.Decide(ctx, pIn)
	if err != nil {
		log.Printf("Policy engine error: %v", err)
		metrics.CheckTotal.WithLabelValues(rc.ID, levelStr, "policy_error").Inc()
		metrics.CheckLatency.WithLabelValues(rc.ID, "policy_error").Observe(time.Since(start).Seconds())

		logging.LogDecision(logging.DecisionLog{
			ResourceID:  rc.ID,
			Level:       levelStr,
			AgentServer: res.Identity.AgentServer,
			Delegate:    res.Identity.Delegate,
			Result:      "policy_error",
			Reason:      err.Error(),
			LatencyMs:   time.Since(start).Milliseconds(),
		})

		built := aauth.NewChallenge(BuildChallengeOptions(rc), err, nil, false).Build()
		return ChallengeToCheckResponse(built), nil
	}

	if !decision.Allow {
		metrics.CheckTotal.WithLabelValues(rc.ID, levelStr, "policy_denied").Inc()
		metrics.CheckLatency.WithLabelValues(rc.ID, "policy_denied").Observe(time.Since(start).Seconds())

		logging.LogDecision(logging.DecisionLog{
			ResourceID:  rc.ID,
			Level:       levelStr,
			AgentServer: res.Identity.AgentServer,
			Delegate:    res.Identity.Delegate,
			Result:      "denied",
			Reason:      decision.Reason,
			LatencyMs:   time.Since(start).Milliseconds(),
		})

		return &pb.CheckResponse{
			Status: &pb.Status{Code: 7}, // PERMISSION_DENIED
			HttpResponse: &pb.CheckResponse_DeniedResponse{
				DeniedResponse: &pb.DeniedHttpResponse{
					Status: &pb.HttpStatus{Code: pb.StatusCode_Forbidden},
					Body:   "Access Denied: " + decision.Reason,
				},
			},
		}, nil
	}

	// Build success response with upstream headers
	upstreamHeaders := IdentityHeadersToProto(res.Identity.Headers())

	metrics.CheckTotal.WithLabelValues(rc.ID, levelStr, "allow").Inc()
	metrics.CheckLatency.WithLabelValues(rc.ID, "allow").Observe(time.Since(start).Seconds())

	logging.LogDecision(logging.DecisionLog{
		ResourceID:  rc.ID,
		Level:       levelStr,
		AgentServer: res.Identity.AgentServer,
		Delegate:    res.Identity.Delegate,
		Result:      "allowed",
		LatencyMs:   time.Since(start).Milliseconds(),
	})

	var headersToRemove []string
	if rc.StripSignatureHeaders {
		headersToRemove = []string{"signature", "signature-input", "signature-key"}
	}

	dynamicMeta, err := IdentityMetadataToStruct(res.Identity.Metadata())
	if err != nil {
		log.Printf("ext_authz dynamic metadata: %v", err)
		dynamicMeta = nil
	}

	return &pb.CheckResponse{
		Status: &pb.Status{Code: 0}, // OK
		HttpResponse: &pb.CheckResponse_OkResponse{
			OkResponse: &pb.OkHttpResponse{
				Headers:         upstreamHeaders,
				HeadersToRemove: headersToRemove,
			},
		},
		DynamicMetadata: dynamicMeta,
	}, nil
}
