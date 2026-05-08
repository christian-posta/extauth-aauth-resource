package headers_test

import (
	"testing"

	"aauth-service/pkg/aauth/headers"
)

func TestParseSignatureError(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		wantCode string
		wantDesc string
		wantErr  bool
	}{
		{
			name:     "invalid_signature",
			input:    `error=invalid_signature`,
			wantCode: "invalid_signature",
		},
		{
			name:     "invalid_input",
			input:    `error=invalid_input`,
			wantCode: "invalid_input",
		},
		{
			name:     "unsupported_algorithm",
			input:    `error=unsupported_algorithm`,
			wantCode: "unsupported_algorithm",
		},
		{
			name:     "invalid_key",
			input:    `error=invalid_key`,
			wantCode: "invalid_key",
		},
		{
			name:     "unknown_key",
			input:    `error=unknown_key`,
			wantCode: "unknown_key",
		},
		{
			name:     "invalid_jwt",
			input:    `error=invalid_jwt`,
			wantCode: "invalid_jwt",
		},
		{
			name:     "expired_jwt",
			input:    `error=expired_jwt`,
			wantCode: "expired_jwt",
		},
		{
			name:     "with description",
			input:    `error=invalid_key, description="key not found"`,
			wantCode: "invalid_key",
			wantDesc: "key not found",
		},
		{
			name:    "missing error member",
			input:   `foo=bar`,
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
			se, err := headers.ParseSignatureError(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if se.Code != tc.wantCode {
				t.Errorf("Code: got %q want %q", se.Code, tc.wantCode)
			}
			if se.Description != tc.wantDesc {
				t.Errorf("Description: got %q want %q", se.Description, tc.wantDesc)
			}
		})
	}
}

func TestBuildSignatureError(t *testing.T) {
	codes := []string{
		headers.ErrCodeInvalidRequest,
		headers.ErrCodeInvalidSignature,
		headers.ErrCodeInvalidInput,
		headers.ErrCodeUnsupportedAlgorithm,
		headers.ErrCodeInvalidKey,
		headers.ErrCodeUnknownKey,
		headers.ErrCodeInvalidJWT,
		headers.ErrCodeExpiredJWT,
	}
	for _, code := range codes {
		t.Run("round-trip/"+code, func(t *testing.T) {
			se := &headers.SignatureError{Code: code}
			s, err := headers.BuildSignatureError(se)
			if err != nil {
				t.Fatalf("build error: %v", err)
			}
			parsed, err := headers.ParseSignatureError(s)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			if parsed.Code != code {
				t.Errorf("Code: got %q want %q", parsed.Code, code)
			}
		})
	}

	t.Run("with description round-trip", func(t *testing.T) {
		orig := &headers.SignatureError{Code: headers.ErrCodeInvalidKey, Description: "key revoked"}
		s, err := headers.BuildSignatureError(orig)
		if err != nil {
			t.Fatalf("build error: %v", err)
		}
		parsed, err := headers.ParseSignatureError(s)
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		if parsed.Description != orig.Description {
			t.Errorf("Description: got %q want %q", parsed.Description, orig.Description)
		}
	})

	t.Run("nil returns error", func(t *testing.T) {
		_, err := headers.BuildSignatureError(nil)
		if err == nil {
			t.Fatal("expected error for nil")
		}
	})

	t.Run("empty code returns error", func(t *testing.T) {
		_, err := headers.BuildSignatureError(&headers.SignatureError{})
		if err == nil {
			t.Fatal("expected error for empty code")
		}
	})
}
