package extauthz

import (
	"context"
	"log"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"

	pb "policy_engine/gen/proto"
	"policy_engine/internal/aauth"
	"policy_engine/internal/config"
	"policy_engine/internal/logging"
	"policy_engine/internal/metrics"
	"policy_engine/internal/policy"
)

type jwksFetcher interface {
	Get(ctx context.Context, uri string) (jwk.Set, error)
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
	authority := httpReq.GetHost()
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
		metrics.CheckTotal.WithLabelValues(rc.ID, levelStr, "error").Inc()
		metrics.CheckLatency.WithLabelValues(rc.ID, "error").Observe(time.Since(start).Seconds())

		logging.LogDecision(logging.DecisionLog{
			ResourceID: rc.ID,
			Level:      levelStr,
			Result:     "error",
			Reason:     res.Err.Error(),
			LatencyMs:  time.Since(start).Milliseconds(),
		})

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
