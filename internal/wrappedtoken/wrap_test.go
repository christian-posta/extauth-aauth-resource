package wrappedtoken_test

import (
	"crypto/rand"
	"testing"
	"time"

	"aauth-service/internal/wrappedtoken"
)

func freshKey() []byte {
	k := make([]byte, 32)
	rand.Read(k)
	return k
}

func TestWrapUnwrapRoundtrip(t *testing.T) {
	key := freshKey()
	tok := wrappedtoken.Token{
		AccessToken:  "gho_test123",
		RefreshToken: "refresh456",
		TokenType:    "bearer",
		Scope:        "read:user",
		AgentJKT:     "thumbprint123",
		IssuedAt:     time.Now().Truncate(time.Second),
	}

	opaque, err := wrappedtoken.Wrap(tok, "resource1", key)
	if err != nil {
		t.Fatal(err)
	}
	if opaque == "" {
		t.Fatal("opaque is empty")
	}

	got, err := wrappedtoken.Unwrap(opaque, "resource1", key)
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessToken != tok.AccessToken {
		t.Errorf("AccessToken: %q != %q", got.AccessToken, tok.AccessToken)
	}
	if got.AgentJKT != tok.AgentJKT {
		t.Errorf("AgentJKT: %q != %q", got.AgentJKT, tok.AgentJKT)
	}
}

func TestWrongResourceID(t *testing.T) {
	key := freshKey()
	tok := wrappedtoken.Token{AccessToken: "tok", AgentJKT: "jkt"}
	opaque, _ := wrappedtoken.Wrap(tok, "resource1", key)

	_, err := wrappedtoken.Unwrap(opaque, "resource2", key)
	if err == nil {
		t.Fatal("expected error decrypting with wrong resourceID")
	}
}

func TestWrongKey(t *testing.T) {
	key1, key2 := freshKey(), freshKey()
	tok := wrappedtoken.Token{AccessToken: "tok", AgentJKT: "jkt"}
	opaque, _ := wrappedtoken.Wrap(tok, "resource1", key1)

	_, err := wrappedtoken.Unwrap(opaque, "resource1", key2)
	if err == nil {
		t.Fatal("expected error decrypting with wrong key")
	}
}

func TestTokenExpiry(t *testing.T) {
	tok := wrappedtoken.Token{
		AccessToken: "tok",
		ExpiresAt:   time.Now().Add(-time.Minute), // already expired
	}
	if !tok.IsExpired() {
		t.Fatal("expected token to be expired")
	}

	tok2 := wrappedtoken.Token{
		AccessToken: "tok",
		ExpiresAt:   time.Now().Add(time.Hour),
	}
	if tok2.IsExpired() {
		t.Fatal("expected token to not be expired")
	}
	if !tok2.ExpiresWithin(2 * time.Hour) {
		t.Fatal("expected ExpiresWithin(2h) to be true")
	}
	if tok2.ExpiresWithin(30 * time.Minute) {
		t.Fatal("expected ExpiresWithin(30m) to be false")
	}
}

func TestNonExpiringToken(t *testing.T) {
	tok := wrappedtoken.Token{AccessToken: "tok"} // zero ExpiresAt
	if tok.IsExpired() {
		t.Fatal("zero ExpiresAt should not be expired")
	}
}
