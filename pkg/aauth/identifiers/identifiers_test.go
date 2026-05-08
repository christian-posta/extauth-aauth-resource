package identifiers_test

import (
	"testing"

	"aauth-service/pkg/aauth/identifiers"
)

func TestValidateServerIdentifier(t *testing.T) {
	valid := []string{
		"https://agent.example",
		"https://xn--nxasmq6b.example",
		"https://resource.example.com",
		"https://a.b.c.d.example",
	}
	for _, s := range valid {
		t.Run("valid/"+s, func(t *testing.T) {
			if err := identifiers.ValidateServerIdentifier(s); err != nil {
				t.Fatalf("expected valid, got error: %v", err)
			}
		})
	}

	invalid := []struct {
		input string
		desc  string
	}{
		{"", "empty string"},
		{"http://agent.example", "wrong scheme (http)"},
		{"ftp://agent.example", "wrong scheme (ftp)"},
		{"agent.example", "no scheme"},
		{"https://Agent.Example", "uppercase hostname"},
		{"https://agent.EXAMPLE", "uppercase TLD"},
		{"https://agent.example:8443", "contains port"},
		{"https://agent.example/v1", "contains path"},
		{"https://agent.example/", "trailing slash"},
		{"https://agent.example?foo=bar", "contains query"},
		{"https://agent.example#frag", "contains fragment"},
		{"https://", "no hostname"},
	}
	for _, tc := range invalid {
		t.Run("invalid/"+tc.desc, func(t *testing.T) {
			if err := identifiers.ValidateServerIdentifier(tc.input); err == nil {
				t.Fatalf("expected error for %q (%s), got nil", tc.input, tc.desc)
			}
		})
	}
}

func TestValidateAgentIdentifier(t *testing.T) {
	valid := []string{
		"aauth:assistant-v2@agent.example",
		"aauth:cli+instance.1@tools.example",
		"aauth:agent@localhost",
		"aauth:agent-8001@127.0.0.1",
		"aauth:a@b.example",
		"aauth:hello_world@example.com",
	}
	for _, s := range valid {
		t.Run("valid/"+s, func(t *testing.T) {
			if err := identifiers.ValidateAgentIdentifier(s); err != nil {
				t.Fatalf("expected valid, got error: %v", err)
			}
		})
	}

	invalid := []struct {
		input string
		desc  string
	}{
		{"", "empty string"},
		{"agent@agent.example", "missing aauth: scheme"},
		{"aauth:", "missing local and domain"},
		{"aauth:@agent.example", "empty local part"},
		{"aauth:agent@", "empty domain part"},
		{"aauth:AGENT@agent.example", "uppercase local part"},
		{"aauth:My Agent@agent.example", "space in local part"},
		{"aauth:agent@http://agent.example", "domain includes scheme"},
		{"http://agent.example", "http scheme instead of aauth"},
	}
	for _, tc := range invalid {
		t.Run("invalid/"+tc.desc, func(t *testing.T) {
			if err := identifiers.ValidateAgentIdentifier(tc.input); err == nil {
				t.Fatalf("expected error for %q (%s), got nil", tc.input, tc.desc)
			}
		})
	}

	t.Run("invalid/local too long", func(t *testing.T) {
		local := ""
		for i := 0; i < 256; i++ {
			local += "a"
		}
		s := "aauth:" + local + "@example.com"
		if err := identifiers.ValidateAgentIdentifier(s); err == nil {
			t.Fatal("expected error for local part > 255 chars, got nil")
		}
	})
}

func TestParseAgentIdentifier(t *testing.T) {
	cases := []struct {
		input        string
		wantLocal    string
		wantDomain   string
		wantErr      bool
	}{
		{"aauth:assistant@agent.example", "assistant", "agent.example", false},
		{"aauth:cli+v1@tools.example", "cli+v1", "tools.example", false},
		{"aauth:agent-8001@127.0.0.1", "agent-8001", "127.0.0.1", false},
		{"agent@example.com", "", "", true},
		{"aauth:@example.com", "", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			local, domain, err := identifiers.ParseAgentIdentifier(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got local=%q domain=%q", local, domain)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if local != tc.wantLocal {
				t.Errorf("local: got %q want %q", local, tc.wantLocal)
			}
			if domain != tc.wantDomain {
				t.Errorf("domain: got %q want %q", domain, tc.wantDomain)
			}
		})
	}
}

func TestAgentIdentifierFromServerURL(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"http://127.0.0.1:8001", "aauth:agent-8001@127.0.0.1"},
		{"http://127.0.0.1:8002", "aauth:agent-8002@127.0.0.1"},
		{"https://agent.example", "aauth:agent@agent.example"},
		{"https://agent.example:443", "aauth:agent-443@agent.example"},
		{"http://localhost", "aauth:agent@localhost"},
	}
	for _, tc := range cases {
		got, err := identifiers.AgentIdentifierFromServerURL(tc.in)
		if err != nil {
			t.Errorf("%s: error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%s: got %q want %q", tc.in, got, tc.want)
		}
	}

	if _, err := identifiers.AgentIdentifierFromServerURL(""); err == nil {
		t.Error("empty URL: expected error")
	}
}

func TestValidateEndpointURL(t *testing.T) {
	valid := []string{
		"https://agent.example/token",
		"https://agent.example",
		"https://agent.example/auth/token",
	}
	for _, s := range valid {
		if err := identifiers.ValidateEndpointURL(s); err != nil {
			t.Errorf("valid %q: %v", s, err)
		}
	}
	invalid := []string{
		"",
		"http://agent.example/token",
		"https://agent.example/token?x=1",
		"https://agent.example/token#frag",
	}
	for _, s := range invalid {
		if err := identifiers.ValidateEndpointURL(s); err == nil {
			t.Errorf("invalid %q: expected error", s)
		}
	}
}

func TestValidateOtherURL(t *testing.T) {
	valid := []string{
		"https://agent.example/jwks.json",
		"https://agent.example",
		"https://agent.example?x=1",
	}
	for _, s := range valid {
		if err := identifiers.ValidateOtherURL(s); err != nil {
			t.Errorf("valid %q: %v", s, err)
		}
	}
	invalid := []string{
		"",
		"http://agent.example/jwks.json",
		"ftp://agent.example",
	}
	for _, s := range invalid {
		if err := identifiers.ValidateOtherURL(s); err == nil {
			t.Errorf("invalid %q: expected error", s)
		}
	}
}
