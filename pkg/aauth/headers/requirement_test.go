package headers_test

import (
	"testing"

	"aauth-service/pkg/aauth/headers"
)

func TestParseAAuthRequirement(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantTyp string
		wantErr bool
		check   func(t *testing.T, reqs []headers.Requirement)
	}{
		{
			name:    "auth-token basic",
			input:   `requirement=auth-token`,
			wantTyp: "auth-token",
		},
		{
			name:    "auth-token with resource-token",
			input:   `requirement=auth-token, resource-token="eyJhbGciOiJFZERTQSJ9.test.sig"`,
			wantTyp: "auth-token",
			check: func(t *testing.T, reqs []headers.Requirement) {
				r := reqs[0].(headers.AuthTokenReq)
				if r.ResourceToken != "eyJhbGciOiJFZERTQSJ9.test.sig" {
					t.Errorf("ResourceToken: got %q", r.ResourceToken)
				}
			},
		},
		{
			name:    "interaction",
			input:   `requirement=interaction, url="https://example.com/interact", code="A1B2-C3D4"`,
			wantTyp: "interaction",
			check: func(t *testing.T, reqs []headers.Requirement) {
				r := reqs[0].(headers.InteractionReq)
				if r.URL != "https://example.com/interact" {
					t.Errorf("URL: got %q", r.URL)
				}
				if r.Code != "A1B2-C3D4" {
					t.Errorf("Code: got %q", r.Code)
				}
			},
		},
		{
			name:    "approval",
			input:   `requirement=approval`,
			wantTyp: "approval",
		},
		{
			name:    "clarification",
			input:   `requirement=clarification`,
			wantTyp: "clarification",
		},
		{
			name:    "claims",
			input:   `requirement=claims`,
			wantTyp: "claims",
		},
		{
			name:    "missing requirement member",
			input:   `foo=bar`,
			wantErr: true,
		},
		{
			name:    "invalid SF",
			input:   `:::`,
			wantErr: true,
		},
		{
			name:    "unknown requirement type",
			input:   `requirement=unknown-type`,
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reqs, err := headers.ParseAAuthRequirement(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (reqs=%v)", reqs)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(reqs) == 0 {
				t.Fatal("expected at least one requirement")
			}
			if reqs[0].Type() != tc.wantTyp {
				t.Errorf("Type: got %q want %q", reqs[0].Type(), tc.wantTyp)
			}
			if tc.check != nil {
				tc.check(t, reqs)
			}
		})
	}
}

func TestBuildAAuthRequirement(t *testing.T) {
	t.Run("auth-token no token", func(t *testing.T) {
		s, err := headers.BuildAAuthRequirement([]headers.Requirement{headers.AuthTokenReq{}})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if s == "" {
			t.Fatal("expected non-empty string")
		}
		// Round-trip
		reqs, err := headers.ParseAAuthRequirement(s)
		if err != nil {
			t.Fatalf("parse round-trip error: %v", err)
		}
		if reqs[0].Type() != "auth-token" {
			t.Errorf("Type: got %q", reqs[0].Type())
		}
	})

	t.Run("auth-token with resource-token round-trip", func(t *testing.T) {
		orig := headers.AuthTokenReq{ResourceToken: "eyJ.test.sig"}
		s, err := headers.BuildAAuthRequirement([]headers.Requirement{orig})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		reqs, err := headers.ParseAAuthRequirement(s)
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		r := reqs[0].(headers.AuthTokenReq)
		if r.ResourceToken != orig.ResourceToken {
			t.Errorf("ResourceToken: got %q want %q", r.ResourceToken, orig.ResourceToken)
		}
	})

	t.Run("interaction round-trip", func(t *testing.T) {
		orig := headers.InteractionReq{URL: "https://example.com/interact", Code: "ABCD"}
		s, err := headers.BuildAAuthRequirement([]headers.Requirement{orig})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		reqs, err := headers.ParseAAuthRequirement(s)
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		r := reqs[0].(headers.InteractionReq)
		if r.URL != orig.URL {
			t.Errorf("URL: got %q want %q", r.URL, orig.URL)
		}
		if r.Code != orig.Code {
			t.Errorf("Code: got %q want %q", r.Code, orig.Code)
		}
	})

	t.Run("empty slice returns error", func(t *testing.T) {
		_, err := headers.BuildAAuthRequirement(nil)
		if err == nil {
			t.Fatal("expected error for empty requirements")
		}
	})
}
