package agent

import (
	"context"
	"net/http"
	"testing"

	"aauth-service/pkg/aauth/headers"
)

func makeResp(statusCode int, hdrs map[string]string) *http.Response {
	resp := &http.Response{
		StatusCode: statusCode,
		Header:     make(http.Header),
	}
	for k, v := range hdrs {
		resp.Header.Set(k, v)
	}
	return resp
}

func TestHandle_AuthTokenReq_RetryJWT(t *testing.T) {
	h := NewChallengeHandler(ChallengeHandlerOptions{})

	reqHdr, err := headers.BuildAAuthRequirement([]headers.Requirement{headers.AuthTokenReq{}})
	if err != nil {
		t.Fatal(err)
	}

	resp := makeResp(401, map[string]string{
		"AAuth-Requirement": reqHdr,
	})

	action, err := h.Handle(context.Background(), resp)
	if err != nil {
		t.Fatalf("Handle error: %v", err)
	}
	if action.Kind != ActionRetry {
		t.Errorf("expected ActionRetry, got %s", action.Kind)
	}
	if action.Retry == nil || action.Retry.Scheme != "jwt" {
		t.Errorf("expected retry scheme=jwt, got %+v", action.Retry)
	}
}

func TestHandle_AcceptSignatureJKT_RetryHWK(t *testing.T) {
	h := NewChallengeHandler(ChallengeHandlerOptions{})

	asHdr, err := headers.BuildAcceptSignature(&headers.AcceptSignature{
		Components: []string{"@method", "@path"},
		KeyTypes:   []string{"jkt"},
	})
	if err != nil {
		t.Fatal(err)
	}

	resp := makeResp(401, map[string]string{
		"Accept-Signature": asHdr,
	})

	action, err := h.Handle(context.Background(), resp)
	if err != nil {
		t.Fatalf("Handle error: %v", err)
	}
	if action.Kind != ActionRetry {
		t.Errorf("expected ActionRetry, got %s", action.Kind)
	}
	if action.Retry == nil || action.Retry.Scheme != "hwk" {
		t.Errorf("expected retry scheme=hwk, got %+v", action.Retry)
	}
	if len(action.Retry.Components) != 2 {
		t.Errorf("expected 2 components, got %d: %v", len(action.Retry.Components), action.Retry.Components)
	}
}

func TestHandle_AcceptSignatureURI_RetryJWKSURI(t *testing.T) {
	h := NewChallengeHandler(ChallengeHandlerOptions{})

	asHdr, err := headers.BuildAcceptSignature(&headers.AcceptSignature{
		Components: []string{"@method"},
		KeyTypes:   []string{"uri"},
		Algorithms: []string{"ed25519"},
	})
	if err != nil {
		t.Fatal(err)
	}

	resp := makeResp(401, map[string]string{
		"Accept-Signature": asHdr,
	})

	action, err := h.Handle(context.Background(), resp)
	if err != nil {
		t.Fatalf("Handle error: %v", err)
	}
	if action.Kind != ActionRetry {
		t.Errorf("expected ActionRetry, got %s", action.Kind)
	}
	if action.Retry == nil || action.Retry.Scheme != "jwks_uri" {
		t.Errorf("expected retry scheme=jwks_uri, got %+v", action.Retry)
	}
	if len(action.Retry.Algorithms) == 0 || action.Retry.Algorithms[0] != "ed25519" {
		t.Errorf("expected algorithms=[ed25519], got %v", action.Retry.Algorithms)
	}
}

func TestHandle_InteractionReq(t *testing.T) {
	h := NewChallengeHandler(ChallengeHandlerOptions{})

	reqHdr, err := headers.BuildAAuthRequirement([]headers.Requirement{
		headers.InteractionReq{URL: "https://auth.example.com/interact", Code: "ABCD"},
	})
	if err != nil {
		t.Fatal(err)
	}

	resp := makeResp(401, map[string]string{
		"AAuth-Requirement": reqHdr,
	})

	action, err := h.Handle(context.Background(), resp)
	if err != nil {
		t.Fatalf("Handle error: %v", err)
	}
	if action.Kind != ActionInteract {
		t.Errorf("expected ActionInteract, got %s", action.Kind)
	}
	if action.InteractionURL != "https://auth.example.com/interact" {
		t.Errorf("unexpected InteractionURL: %s", action.InteractionURL)
	}
	if action.InteractionCode != "ABCD" {
		t.Errorf("unexpected InteractionCode: %s", action.InteractionCode)
	}
}

func TestHandle_ApprovalReq(t *testing.T) {
	h := NewChallengeHandler(ChallengeHandlerOptions{})

	reqHdr, err := headers.BuildAAuthRequirement([]headers.Requirement{headers.ApprovalReq{}})
	if err != nil {
		t.Fatal(err)
	}

	resp := makeResp(403, map[string]string{
		"AAuth-Requirement": reqHdr,
	})

	action, err := h.Handle(context.Background(), resp)
	if err != nil {
		t.Fatalf("Handle error: %v", err)
	}
	if action.Kind != ActionApprove {
		t.Errorf("expected ActionApprove, got %s", action.Kind)
	}
}

func TestHandle_SignatureError_Propagated(t *testing.T) {
	h := NewChallengeHandler(ChallengeHandlerOptions{})

	seHdr, err := headers.BuildSignatureError(&headers.SignatureError{
		Code:        headers.ErrCodeInvalidSignature,
		Description: "signature did not verify",
	})
	if err != nil {
		t.Fatal(err)
	}

	resp := makeResp(401, map[string]string{
		"Signature-Error": seHdr,
	})

	action, err := h.Handle(context.Background(), resp)
	if err != nil {
		t.Fatalf("Handle error: %v", err)
	}
	if action.Error == "" {
		t.Error("expected Error field to be set")
	}
	if action.Kind != ActionFail {
		t.Errorf("expected ActionFail, got %s", action.Kind)
	}
}

func TestHandle_EmptyResponse_Fail(t *testing.T) {
	h := NewChallengeHandler(ChallengeHandlerOptions{})

	resp := makeResp(401, nil)

	action, err := h.Handle(context.Background(), resp)
	if err != nil {
		t.Fatalf("Handle error: %v", err)
	}
	if action.Kind != ActionFail {
		t.Errorf("expected ActionFail, got %s", action.Kind)
	}
}

func TestHandle_ClarificationReq(t *testing.T) {
	h := NewChallengeHandler(ChallengeHandlerOptions{})

	reqHdr, err := headers.BuildAAuthRequirement([]headers.Requirement{headers.ClarificationReq{}})
	if err != nil {
		t.Fatal(err)
	}

	resp := makeResp(401, map[string]string{
		"AAuth-Requirement": reqHdr,
	})

	action, err := h.Handle(context.Background(), resp)
	if err != nil {
		t.Fatalf("Handle error: %v", err)
	}
	if action.Kind != ActionClarify {
		t.Errorf("expected ActionClarify, got %s", action.Kind)
	}
}
