package headers_test

import (
	"testing"

	"aauth-service/pkg/aauth/headers"
)

func TestParseCapabilities(t *testing.T) {
	cases := []struct {
		name   string
		input  string
		want   headers.Capabilities
		wantErr bool
	}{
		{
			name:  "interaction only",
			input: "interaction",
			want:  headers.Capabilities{Interaction: true},
		},
		{
			name:  "clarification only",
			input: "clarification",
			want:  headers.Capabilities{Clarification: true},
		},
		{
			name:  "payment only",
			input: "payment",
			want:  headers.Capabilities{Payment: true},
		},
		{
			name:  "all capabilities",
			input: "interaction, clarification, payment",
			want:  headers.Capabilities{Interaction: true, Clarification: true, Payment: true},
		},
		{
			name:  "with extra whitespace",
			input: " interaction , clarification ",
			want:  headers.Capabilities{Interaction: true, Clarification: true},
		},
		{
			name:    "empty value",
			input:   "",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := headers.ParseCapabilities(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if c.Interaction != tc.want.Interaction {
				t.Errorf("Interaction: got %v want %v", c.Interaction, tc.want.Interaction)
			}
			if c.Clarification != tc.want.Clarification {
				t.Errorf("Clarification: got %v want %v", c.Clarification, tc.want.Clarification)
			}
			if c.Payment != tc.want.Payment {
				t.Errorf("Payment: got %v want %v", c.Payment, tc.want.Payment)
			}
		})
	}
}

func TestBuildCapabilities(t *testing.T) {
	t.Run("round-trip all", func(t *testing.T) {
		orig := &headers.Capabilities{Interaction: true, Clarification: true, Payment: true}
		s, err := headers.BuildCapabilities(orig)
		if err != nil {
			t.Fatalf("build error: %v", err)
		}
		parsed, err := headers.ParseCapabilities(s)
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		if parsed.Interaction != orig.Interaction || parsed.Clarification != orig.Clarification || parsed.Payment != orig.Payment {
			t.Errorf("round-trip mismatch: got %+v want %+v", parsed, orig)
		}
	})

	t.Run("none set produces empty string", func(t *testing.T) {
		s, err := headers.BuildCapabilities(&headers.Capabilities{})
		if err != nil {
			t.Fatalf("build error: %v", err)
		}
		if s != "" {
			t.Errorf("expected empty string for no capabilities, got %q", s)
		}
	})

	t.Run("nil returns error", func(t *testing.T) {
		_, err := headers.BuildCapabilities(nil)
		if err == nil {
			t.Fatal("expected error for nil input")
		}
	})
}
