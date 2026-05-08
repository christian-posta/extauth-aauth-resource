package headers_test

import (
	"encoding/json"
	"os"
	"testing"

	"aauth-service/pkg/aauth/headers"
)

func TestGoldenMissionFixture(t *testing.T) {
	data, err := os.ReadFile("testdata/mission_valid.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fix struct {
		Header       string `json:"header"`
		WantApprover string `json:"want_approver"`
		WantHash     string `json:"want_hash"`
	}
	if err := json.Unmarshal(data, &fix); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	m, err := headers.ParseMission(fix.Header)
	if err != nil {
		t.Fatalf("ParseMission: %v", err)
	}
	if m.Approver != fix.WantApprover {
		t.Errorf("Approver: got %q want %q", m.Approver, fix.WantApprover)
	}
	if m.Hash != fix.WantHash {
		t.Errorf("Hash: got %q want %q", m.Hash, fix.WantHash)
	}
}

func TestGoldenRequirementAuthToken(t *testing.T) {
	data, err := os.ReadFile("testdata/requirement_auth_token.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fix struct {
		Header            string `json:"header"`
		WantType          string `json:"want_type"`
		WantResourceToken string `json:"want_resource_token"`
	}
	if err := json.Unmarshal(data, &fix); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	reqs, err := headers.ParseAAuthRequirement(fix.Header)
	if err != nil {
		t.Fatalf("ParseAAuthRequirement: %v", err)
	}
	if reqs[0].Type() != fix.WantType {
		t.Errorf("Type: got %q want %q", reqs[0].Type(), fix.WantType)
	}
	r := reqs[0].(headers.AuthTokenReq)
	if r.ResourceToken != fix.WantResourceToken {
		t.Errorf("ResourceToken: got %q want %q", r.ResourceToken, fix.WantResourceToken)
	}
}

func TestGoldenRequirementInteraction(t *testing.T) {
	data, err := os.ReadFile("testdata/requirement_interaction.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fix struct {
		Header   string `json:"header"`
		WantType string `json:"want_type"`
		WantURL  string `json:"want_url"`
		WantCode string `json:"want_code"`
	}
	if err := json.Unmarshal(data, &fix); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	reqs, err := headers.ParseAAuthRequirement(fix.Header)
	if err != nil {
		t.Fatalf("ParseAAuthRequirement: %v", err)
	}
	if reqs[0].Type() != fix.WantType {
		t.Errorf("Type: got %q want %q", reqs[0].Type(), fix.WantType)
	}
	r := reqs[0].(headers.InteractionReq)
	if r.URL != fix.WantURL {
		t.Errorf("URL: got %q want %q", r.URL, fix.WantURL)
	}
	if r.Code != fix.WantCode {
		t.Errorf("Code: got %q want %q", r.Code, fix.WantCode)
	}
}

func TestGoldenAcceptSignature(t *testing.T) {
	data, err := os.ReadFile("testdata/accept_signature.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fix struct {
		Header         string   `json:"header"`
		WantKeyTypes   []string `json:"want_key_types"`
		WantComponents []string `json:"want_components"`
	}
	if err := json.Unmarshal(data, &fix); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	as, err := headers.ParseAcceptSignature(fix.Header)
	if err != nil {
		t.Fatalf("ParseAcceptSignature: %v", err)
	}
	if !stringSlicesEqual(as.KeyTypes, fix.WantKeyTypes) {
		t.Errorf("KeyTypes: got %v want %v", as.KeyTypes, fix.WantKeyTypes)
	}
	for _, wantComp := range fix.WantComponents {
		found := false
		for _, c := range as.Components {
			if c == wantComp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected component %q in %v", wantComp, as.Components)
		}
	}
}
