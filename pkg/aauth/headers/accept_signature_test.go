package headers_test

import (
	"testing"

	"aauth-service/pkg/aauth/headers"
)

func TestParseAcceptSignature(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		wantKTs   []string
		wantComps []string
		wantAlgs  []string
		wantErr   bool
	}{
		{
			name:      "single jkt entry",
			input:     `sig1=("@method" "@authority" "@path");sigkey=jkt`,
			wantKTs:   []string{"jkt"},
			wantComps: []string{"@method", "@authority", "@path"},
		},
		{
			name:      "single uri entry",
			input:     `sig1=("@method" "@authority" "@path");sigkey=uri`,
			wantKTs:   []string{"uri"},
			wantComps: []string{"@method", "@authority", "@path"},
		},
		{
			name:      "two entries jkt and uri",
			input:     `sig1=("@method" "@authority" "@path");sigkey=jkt, sig2=("@method" "@authority" "@path");sigkey=uri`,
			wantKTs:   []string{"jkt", "uri"},
			wantComps: []string{"@method", "@authority", "@path"},
		},
		{
			name:      "with algorithm",
			input:     `sig1=("@method" "@authority" "@path");alg="ed25519";sigkey=jkt`,
			wantKTs:   []string{"jkt"},
			wantComps: []string{"@method", "@authority", "@path"},
			wantAlgs:  []string{"ed25519"},
		},
		{
			name:    "empty value",
			input:   "",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			as, err := headers.ParseAcceptSignature(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !stringSlicesEqual(as.KeyTypes, tc.wantKTs) {
				t.Errorf("KeyTypes: got %v want %v", as.KeyTypes, tc.wantKTs)
			}
			for _, comp := range tc.wantComps {
				found := false
				for _, c := range as.Components {
					if c == comp {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected component %q in %v", comp, as.Components)
				}
			}
			if len(tc.wantAlgs) > 0 && !stringSlicesEqual(as.Algorithms, tc.wantAlgs) {
				t.Errorf("Algorithms: got %v want %v", as.Algorithms, tc.wantAlgs)
			}
		})
	}
}

func TestBuildAcceptSignature(t *testing.T) {
	t.Run("single jkt round-trip", func(t *testing.T) {
		orig := &headers.AcceptSignature{
			Components: []string{"@method", "@authority", "@path"},
			KeyTypes:   []string{"jkt"},
		}
		s, err := headers.BuildAcceptSignature(orig)
		if err != nil {
			t.Fatalf("build error: %v", err)
		}
		parsed, err := headers.ParseAcceptSignature(s)
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		if !stringSlicesEqual(parsed.KeyTypes, orig.KeyTypes) {
			t.Errorf("KeyTypes: got %v want %v", parsed.KeyTypes, orig.KeyTypes)
		}
	})

	t.Run("jkt and uri round-trip", func(t *testing.T) {
		orig := &headers.AcceptSignature{
			Components: []string{"@method", "@authority", "@path"},
			KeyTypes:   []string{"jkt", "uri"},
		}
		s, err := headers.BuildAcceptSignature(orig)
		if err != nil {
			t.Fatalf("build error: %v", err)
		}
		parsed, err := headers.ParseAcceptSignature(s)
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		if !stringSlicesEqual(parsed.KeyTypes, orig.KeyTypes) {
			t.Errorf("KeyTypes: got %v want %v", parsed.KeyTypes, orig.KeyTypes)
		}
	})

	t.Run("nil input returns error", func(t *testing.T) {
		_, err := headers.BuildAcceptSignature(nil)
		if err == nil {
			t.Fatal("expected error for nil input")
		}
	})
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
