package aauth

import "net/http"

type Level string

const (
	LevelPseudonymous Level = "pseudonymous"
	LevelIdentified   Level = "identified"
	LevelAuthorized   Level = "authorized"
)

type Identity struct {
	Level       Level
	Scheme      string
	TokenType   string
	Issuer      string
	KeyID       string
	AgentServer string
	Delegate    string
	Scope       string
	// ActSub is RFC 8693 act.sub from aa-auth+jwt (the acting agent). Empty for other verification paths.
	ActSub string
	Txn    string
	JKT    string
}

// Headers returns the x-aauth-* upstream headers describing this identity.
// Empty fields are omitted. Keys are kept lower-case (no canonicalization)
// so callers can forward them verbatim without surprises.
func (id Identity) Headers() http.Header {
	headers := http.Header{}
	add := func(k, v string) {
		if v != "" {
			headers[k] = []string{v}
		}
	}

	add("x-aauth-level", string(id.Level))
	add("x-aauth-agent-server", id.AgentServer)
	add("x-aauth-delegate", id.Delegate)
	add("x-aauth-scope", id.Scope)
	add("x-aauth-txn", id.Txn)
	add("x-aauth-jkt", id.JKT)

	return headers
}

// Metadata returns a plain map describing this identity for downstream policy
// engines (e.g. Envoy ext_authz dynamic metadata, CEL). Returns nil when there
// is no identity to describe.
func (id Identity) Metadata() map[string]any {
	if id.Level == "" {
		return nil
	}
	fields := map[string]any{
		"level": string(id.Level),
	}
	if id.Scheme != "" {
		fields["scheme"] = id.Scheme
	}
	if id.TokenType != "" {
		fields["token_type"] = id.TokenType
	}
	if id.Issuer != "" {
		fields["issuer"] = id.Issuer
	}
	if id.KeyID != "" {
		fields["key_id"] = id.KeyID
	}
	if id.JKT != "" {
		fields["jkt"] = id.JKT
	}
	if id.Level == LevelAuthorized && id.AgentServer != "" {
		fields["agent"] = id.AgentServer
	}
	if id.Level == LevelIdentified && id.AgentServer != "" {
		fields["agent_server"] = id.AgentServer
	}
	if id.Scope != "" {
		fields["scope"] = id.Scope
	}
	if id.Txn != "" {
		fields["txn"] = id.Txn
	}
	if id.ActSub != "" {
		fields["act"] = map[string]any{"sub": id.ActSub}
	}
	if id.Delegate != "" {
		fields["sub"] = id.Delegate
	}
	if len(fields) == 0 {
		return nil
	}
	return fields
}
