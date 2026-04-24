package aauth

import "testing"

func TestIssAllowedInAAuthJWT(t *testing.T) {
	cases := []struct {
		iss             string
		allowInsecure   bool
		want            bool
		comment         string
	}{
		{"", false, false, "empty"},
		{"", true, false, "empty with insecure"},
		{"https://a.example", false, true, "https default"},
		{"https://a.example", true, true, "https with insecure"},
		{"http://127.0.0.1:8765", false, false, "http loopback strict"},
		{"http://127.0.0.1:8765", true, true, "http loopback demo"},
		{"http://localhost:8080", true, true, "http localhost demo"},
		{"http://evil.com", true, false, "http public host not allowed even with flag"},
	}
	for _, c := range cases {
		if got := issAllowedInAAuthJWT(c.iss, c.allowInsecure); got != c.want {
			t.Errorf("iss=%q allowInsecure=%v: got %v want %v (%s)", c.iss, c.allowInsecure, got, c.want, c.comment)
		}
	}
}
