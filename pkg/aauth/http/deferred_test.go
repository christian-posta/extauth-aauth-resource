package http_test

import (
	"testing"

	ahttp "aauth-service/pkg/aauth/http"
)

func TestStatusConstants(t *testing.T) {
	if ahttp.StatusPending != "pending" {
		t.Errorf("StatusPending = %q, want %q", ahttp.StatusPending, "pending")
	}
	if ahttp.StatusInteracting != "interacting" {
		t.Errorf("StatusInteracting = %q, want %q", ahttp.StatusInteracting, "interacting")
	}
	if ahttp.StatusCompleted != "completed" {
		t.Errorf("StatusCompleted = %q, want %q", ahttp.StatusCompleted, "completed")
	}
}

func TestCodeConstants(t *testing.T) {
	if ahttp.CodeSuccess != 200 {
		t.Errorf("CodeSuccess = %d, want 200", ahttp.CodeSuccess)
	}
	if ahttp.CodeDenied != 403 {
		t.Errorf("CodeDenied = %d, want 403", ahttp.CodeDenied)
	}
	if ahttp.CodeExpired != 408 {
		t.Errorf("CodeExpired = %d, want 408", ahttp.CodeExpired)
	}
	if ahttp.CodeCancelled != 410 {
		t.Errorf("CodeCancelled = %d, want 410", ahttp.CodeCancelled)
	}
}

func TestDeferredResponseFields(t *testing.T) {
	d := ahttp.DeferredResponse{
		Status:      ahttp.StatusPending,
		Location:    "http://example.com/poll/123",
		RetryAfter:  5,
		Requirement: "interaction",
		URL:         "http://example.com/interact",
		Code:        "abc123",
		Clarification:      "Please approve",
		Token:       "some.jwt.token",
	}
	if d.Status != "pending" {
		t.Errorf("Status = %q", d.Status)
	}
	if d.Location != "http://example.com/poll/123" {
		t.Errorf("Location = %q", d.Location)
	}
	if d.RetryAfter != 5 {
		t.Errorf("RetryAfter = %d", d.RetryAfter)
	}
	if d.Requirement != "interaction" {
		t.Errorf("Requirement = %q", d.Requirement)
	}
	if d.URL != "http://example.com/interact" {
		t.Errorf("URL = %q", d.URL)
	}
	if d.Code != "abc123" {
		t.Errorf("Code = %q", d.Code)
	}
	if d.Clarification != "Please approve" {
		t.Errorf("Clarification = %q", d.Clarification)
	}
	if d.Token != "some.jwt.token" {
		t.Errorf("Token = %q", d.Token)
	}
}
