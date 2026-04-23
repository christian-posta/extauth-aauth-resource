package extauthz

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"

	pb "aauth-service/gen/proto"
	"aauth-service/internal/aauth"
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
}

func NewAAuthHandler(engine policy.Engine, jwksClient jwksFetcher) *AAuthHandler {
	return &AAuthHandler{
		policyEngine: engine,
		jwksClient:   jwksClient,
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

	start := time.Now()
	res := aauth.Verify(rc, method, authority, path, headers, h.jwksClient)

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

		logging.LogDecision(logging.DecisionLog{
			ResourceID: rc.ID,
			Level:      levelStr,
			Result:     "error",
			Reason:     reason,
			LatencyMs:  time.Since(start).Milliseconds(),
		})
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

		challenge := aauth.NewChallenge(rc, res.Err, hint, issueToken)
		return challenge.Response(), nil
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

		return aauth.NewChallenge(rc, err, nil, false).Response(), nil
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
	upstreamHeaders := aauth.ToUpstreamHeaders(res.Identity)

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

	return &pb.CheckResponse{
		Status: &pb.Status{Code: 0}, // OK
		HttpResponse: &pb.CheckResponse_OkResponse{
			OkResponse: &pb.OkHttpResponse{
				Headers:         upstreamHeaders,
				HeadersToRemove: headersToRemove,
			},
		},
	}, nil
}
