package headers_test

import (
	"testing"

	"aauth-service/pkg/aauth/headers"
)

func TestParseMission(t *testing.T) {
	cases := []struct {
		name         string
		input        string
		wantApprover string
		wantHash     string
		wantErr      bool
	}{
		{
			name:         "valid mission",
			input:        `approver="https://ps.example", s256="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"`,
			wantApprover: "https://ps.example",
			wantHash:     "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		},
		{
			name:         "spec example format",
			input:        `approver="https://ps.example"; s256="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"`,
			wantApprover: "https://ps.example",
			wantHash:     "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		},
		{
			name:    "missing approver",
			input:   `s256="abc123"`,
			wantErr: true,
		},
		{
			name:    "missing s256",
			input:   `approver="https://ps.example"`,
			wantErr: true,
		},
		{
			name:    "invalid SF",
			input:   `:::`,
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := headers.ParseMission(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (m=%+v)", m)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if m.Approver != tc.wantApprover {
				t.Errorf("Approver: got %q want %q", m.Approver, tc.wantApprover)
			}
			if m.Hash != tc.wantHash {
				t.Errorf("Hash: got %q want %q", m.Hash, tc.wantHash)
			}
		})
	}
}

func TestBuildMission(t *testing.T) {
	t.Run("round-trip", func(t *testing.T) {
		orig := &headers.Mission{
			Approver: "https://ps.example",
			Hash:     "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		}
		s, err := headers.BuildMission(orig)
		if err != nil {
			t.Fatalf("build error: %v", err)
		}
		parsed, err := headers.ParseMission(s)
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		if parsed.Approver != orig.Approver {
			t.Errorf("Approver: got %q want %q", parsed.Approver, orig.Approver)
		}
		if parsed.Hash != orig.Hash {
			t.Errorf("Hash: got %q want %q", parsed.Hash, orig.Hash)
		}
	})

	t.Run("nil returns error", func(t *testing.T) {
		_, err := headers.BuildMission(nil)
		if err == nil {
			t.Fatal("expected error for nil")
		}
	})

	t.Run("empty approver returns error", func(t *testing.T) {
		_, err := headers.BuildMission(&headers.Mission{Hash: "abc"})
		if err == nil {
			t.Fatal("expected error for empty approver")
		}
	})

	t.Run("empty hash returns error", func(t *testing.T) {
		_, err := headers.BuildMission(&headers.Mission{Approver: "https://ps.example"})
		if err == nil {
			t.Fatal("expected error for empty hash")
		}
	})
}
