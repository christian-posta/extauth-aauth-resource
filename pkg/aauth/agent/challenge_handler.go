package agent

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"aauth-service/pkg/aauth/headers"
)

// ActionKind describes what an agent should do in response to a challenge.
type ActionKind string

const (
	ActionRetry    ActionKind = "retry"
	ActionInteract ActionKind = "interact"
	ActionClarify  ActionKind = "clarify"
	ActionApprove  ActionKind = "approve"
	ActionFail     ActionKind = "fail"
)

// RetryPlan carries parameters for resubmitting the request.
type RetryPlan struct {
	Scheme     string
	Components []string
	Algorithms []string
}

// Action is the structured result of challenge parsing.
type Action struct {
	Kind                ActionKind
	Requirements        []headers.Requirement
	Retry               *RetryPlan
	InteractionURL      string
	InteractionCode     string
	ClarificationPrompt string
	Error               string
}

// ChallengeHandlerOptions configures a ChallengeHandler.
type ChallengeHandlerOptions struct {
	Logger *slog.Logger
}

// ChallengeHandler inspects non-2xx responses and returns structured Actions.
type ChallengeHandler struct {
	logger *slog.Logger
}

// NewChallengeHandler returns a ChallengeHandler.
func NewChallengeHandler(opts ChallengeHandlerOptions) *ChallengeHandler {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &ChallengeHandler{logger: logger}
}

// Handle inspects a non-2xx response and returns an Action.
func (h *ChallengeHandler) Handle(ctx context.Context, resp *http.Response) (*Action, error) {
	action := &Action{}

	sigErrVal := resp.Header.Get(headers.HeaderSignatureError)
	if sigErrVal != "" {
		se, err := headers.ParseSignatureError(sigErrVal)
		if err == nil {
			desc := se.Code
			if se.Description != "" {
				desc = fmt.Sprintf("%s: %s", se.Code, se.Description)
			}
			action.Error = desc
		} else {
			action.Error = sigErrVal
		}
	}

	var reqs []headers.Requirement
	if reqVal := resp.Header.Get(headers.HeaderAAuthRequirement); reqVal != "" {
		parsed, err := headers.ParseAAuthRequirement(reqVal)
		if err != nil {
			h.logger.WarnContext(ctx, "failed to parse AAuth-Requirement", "error", err)
		} else {
			reqs = parsed
		}
	}
	action.Requirements = reqs

	var acceptSig *headers.AcceptSignature
	if asVal := resp.Header.Get(headers.HeaderAcceptSignature); asVal != "" {
		parsed, err := headers.ParseAcceptSignature(asVal)
		if err != nil {
			h.logger.WarnContext(ctx, "failed to parse Accept-Signature", "error", err)
		} else {
			acceptSig = parsed
		}
	}

	for _, req := range reqs {
		switch r := req.(type) {
		case headers.InteractionReq:
			action.Kind = ActionInteract
			action.InteractionURL = r.URL
			action.InteractionCode = r.Code
			return action, nil

		case headers.ClarificationReq:
			action.Kind = ActionClarify
			action.ClarificationPrompt = r.Prompt
			return action, nil

		case headers.ApprovalReq:
			action.Kind = ActionApprove
			return action, nil

		case headers.AuthTokenReq:
			action.Kind = ActionRetry
			action.Retry = retryPlanFromAcceptSig("jwt", acceptSig)
			return action, nil
		}
	}

	if acceptSig != nil {
		for _, kt := range acceptSig.KeyTypes {
			switch kt {
			case "uri":
				action.Kind = ActionRetry
				action.Retry = retryPlanFromAcceptSig("jwks_uri", acceptSig)
				return action, nil
			case "jkt":
				action.Kind = ActionRetry
				action.Retry = retryPlanFromAcceptSig("hwk", acceptSig)
				return action, nil
			}
		}

		if len(acceptSig.KeyTypes) == 0 {
			action.Kind = ActionRetry
			action.Retry = retryPlanFromAcceptSig("hwk", acceptSig)
			return action, nil
		}
	}

	action.Kind = ActionFail
	if action.Error == "" {
		action.Error = "no actionable challenge found in response"
	}
	return action, nil
}

func retryPlanFromAcceptSig(scheme string, as *headers.AcceptSignature) *RetryPlan {
	plan := &RetryPlan{Scheme: scheme}
	if as != nil {
		plan.Components = as.Components
		plan.Algorithms = as.Algorithms
	}
	return plan
}
