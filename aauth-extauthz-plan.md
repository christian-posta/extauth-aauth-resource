# AAuth Resource-Side ExtAuthZ Service — Implementation Plan

This plan extends the existing `extauth-policy-engine` (Go / Envoy ExtAuthZ gRPC) into a multi-tenant AAuth resource-side service. It is written to be handed directly to Claude Code. Ship in phases; each phase has its own deliverables and acceptance criteria.

---

## 0. Goal and scope

### What we're building
A single Go binary that lets anyone protect one or more backend APIs (REST, MCP servers, etc.) with the AAuth protocol by deploying it behind `agentgateway.dev` (or any Envoy ExtAuthZ client) — with **zero code changes to agentgateway core**.

### In scope (POC)
- RFC 9421 HTTP Message Signature verification on every request
- `Signature-Key` header per Dick Hardt's draft, schemes: `hwk`, `jwt`, `jwks_uri`
- AAuth identity levels: pseudonymous, identified (agent tokens), authorized (auth tokens)
- Per-resource config (multi-tenant) — one deployment can front multiple protected resources selected per route
- `/.well-known/aauth-resource.json` and `/.well-known/jwks.json` served directly
- `POST /resource/token` endpoint for out-of-band resource-token requests
- 401 challenges with `AAuth-Requirement` header (RFC 8941 Dictionary) embedding a freshly-minted resource-token
- Header mutations on the upstream request conveying verified identity

### Out of scope / explicitly deferred
- Request body signing (`content-digest`) — revisit if a demo needs it
- Multi-hop / call-chaining (resource acting as an agent)
- `x509` Signature-Key scheme
- Encrypted auth tokens (JWE)
- Revocation endpoint
- `AAuth-Session` header
- Deferred/polling (`202`) responses — the resource returns terminal decisions
- Dynamic resource registration

### Non-negotiables
- Do **not** modify the ExtAuthZ gRPC interface shape. The existing `Check()` handler is the entry point — we extend its logic.
- Build the RFC 9421 + signature-key implementations **from scratch** in `pkg/httpsig` and `pkg/sigkey`. No wrapping third-party libs. These should be reusable outside this service.
- The policy layer is a **thin interface only** — no OPA/OpenFGA/rego. A default "allow if AAuth succeeds" implementation is fine. Keep the existing inline-Go rules behind a non-AAuth legacy path for routes that opt out.

---

## 1. High-level architecture

One binary, three listeners:

```
Agent ──HTTP──▶ agentgateway
                    │
      ┌─── /.well-known/aauth-resource.json ──┐
      │    /.well-known/jwks.json              │  (routed directly to aauth-service HTTP,
      │    /resource/token                    │   no extauthz filter on these)
      │                                        ▼
      │                              aauth-service :8080 (HTTP)
      │
      └─── everything else  ──▶ extauthz filter
                                        │
                                        ▼
                              aauth-service :9090 (gRPC)
                              (existing Check() handler, extended)
                                        │
                         OK / 401 ◀─────┘
                              │
                              ▼
                         agentgateway ─▶ backend
```

### Route-to-resource mapping
- **ExtAuthZ path**: agentgateway passes `context_extensions.aauth_resource_id` on each route. The Check handler uses that to look up the `ResourceConfig`. Already supported by the existing code via `attrs.GetContextExtensions()` — no new wire format needed.
- **HTTP endpoints**: the service maps the inbound `Host` header to a `ResourceConfig`. Host-based because metadata must live at the resource's own HTTPS URL.

---

## 2. Configuration model

One YAML file, loaded at startup. Hot reload is nice-to-have (SIGHUP) but not required for POC.

```yaml
listen:
  grpc: ":9090"       # ExtAuthZ
  http: ":8080"       # protocol endpoints

jwks_cache:
  success_ttl: 5m
  error_ttl: 30s
  max_entries: 1000

resources:
  - id: openai-api                              # matches context_extensions.aauth_resource_id
    issuer: https://openai-api.example.com      # canonical resource URL; appears in iss claims
    hosts:                                      # Host-header values served by HTTP endpoints
      - openai-api.example.com
    signing_key:                                # for signing resource-tokens; public half served at jwks.json
      kid: rsk-1
      alg: EdDSA
      private_key_file: /etc/aauth/openai-api/ed25519.pem
    signature_window: 60s                       # RFC 9421 `created` tolerance (each side)
    additional_signature_components: []         # e.g. ["content-type"]; content-digest NOT supported yet
    supported_scopes:
      - openai.chat.read
      - openai.chat.write
    scope_descriptions:
      openai.chat.read: "Read chat completions"
      openai.chat.write: "Send chat completions"
    authorization_endpoint: https://as.example.com/authorize
    allow_pseudonymous: true                    # accept scheme=hwk at all?
    strip_signature_headers: true               # strip Signature* before forwarding upstream
    auth_servers:                               # whitelist of ASes whose auth-tokens we accept
      - issuer: https://as.example.com
        jwks_uri: https://as.example.com/.well-known/jwks.json
    agent_servers:                              # whitelist of agent servers for identified requests
      - issuer: https://agents.example.com
        jwks_uri: https://agents.example.com/.well-known/jwks.json
    policy:
      name: default                             # selects a PolicyEngine implementation; "default" = allow

  - id: internal-mcp
    issuer: https://mcp.example.com
    hosts: [mcp.example.com]
    ...
```

Validate on load: unique `id`s, unique `host`s across resources, private key exists and parses, `auth_servers` / `agent_servers` URIs are HTTPS, `authorization_endpoint` is HTTPS.

---

## 3. Repo layout

Refactor the current single `main.go` into this structure. Preserve existing non-AAuth behavior on a legacy code path for routes without `aauth_resource_id`.

```
extauth-policy-engine/
├── cmd/server/main.go               # flag parsing, config load, wire up servers
├── internal/
│   ├── config/
│   │   ├── config.go                # Root + YAML load + validate
│   │   └── resource.go              # ResourceConfig types
│   ├── resource/
│   │   ├── registry.go              # ByID / ByHost lookup
│   │   └── keys.go                  # per-resource signing key loading
│   ├── extauthz/
│   │   ├── server.go                # gRPC boot
│   │   ├── handler.go               # Check() dispatcher: AAuth vs legacy
│   │   ├── aauth.go                 # AAuth-specific Check logic
│   │   ├── legacy.go                # existing rules from current main.go
│   │   └── response.go              # OK/Deny builders + header utilities
│   ├── httpapi/
│   │   ├── server.go                # HTTP boot
│   │   ├── metadata.go              # GET /.well-known/aauth-resource.json
│   │   ├── jwks.go                  # GET /.well-known/jwks.json
│   │   └── resource_token.go        # POST /resource/token
│   ├── aauth/
│   │   ├── verify.go                # orchestrates sigkey parse + httpsig verify + token checks
│   │   ├── tokens.go                # mint resource-tokens; parse/verify agent+jwt and auth+jwt
│   │   ├── challenge.go             # build AAuth-Requirement 401 response
│   │   ├── identity.go              # extracted identity → upstream header mutations
│   │   └── errors.go                # AAuth error codes (invalid_signature, invalid_token, ...)
│   ├── jwksfetch/
│   │   ├── client.go                # HTTP fetcher with allowlist
│   │   └── cache.go                 # TTL cache + negative cache + kid-miss refresh
│   └── policy/
│       ├── engine.go                # interface (see §11)
│       └── default.go               # allow-all-after-aauth default
├── pkg/
│   ├── httpsig/                     # RFC 9421 — reusable lib
│   │   ├── structfields/            # RFC 8941 Structured Fields (Dict, List, Item, Params)
│   │   │   ├── parse.go
│   │   │   └── serialize.go
│   │   ├── components.go            # @method, @authority, @path, signature-key, header fields
│   │   ├── base.go                  # signature base construction
│   │   ├── input.go                 # Signature-Input parsing
│   │   ├── algorithms.go            # EdDSA (Ed25519), ES256 (deterministic P-256)
│   │   ├── verifier.go              # Verify() entry
│   │   └── signer.go                # Sign() entry (needed for tokens/tests)
│   └── sigkey/                      # Signature-Key header (Hardt draft)
│       ├── parse.go                 # Structured Dict parsing
│       ├── schemes.go               # hwk | jwt | jwks_uri | x509(stub)
│       └── types.go                 # Parsed, Scheme enum
└── testdata/
    ├── keys/                        # test Ed25519 + P-256 keys
    ├── jwks/                        # fake AS / agent-server JWKS
    └── vectors/                     # known-good signed requests for regression
```

---

## 4. RFC 9421 + signature-key library design (`pkg/httpsig`, `pkg/sigkey`)

This is the foundation. Get it right and correct, with crisp tests, before touching the service layer.

### 4.1 Scope decisions

- **Verify-primary, sign-secondary.** The service's dominant path is verification of inbound requests. Signing is needed only to mint resource-tokens (JWT-level signing, not HTTPSig signing) and to produce test fixtures. Keep `Sign()` minimal.
- **Algorithms**: EdDSA over Ed25519 (AAuth MUST), ECDSA over P-256 with deterministic nonces per RFC 6979 (AAuth SHOULD). Nothing else for POC.
- **Components supported at build time**:
  - Derived: `@method`, `@authority`, `@path` (that's all AAuth mandates; add `@target-uri`, `@query`, `@status` later if asked).
  - Header fields: any header referenced by name in `Signature-Input`, with the special case that `signature-key` is always allowed even though it's the keying material itself (that's the whole point — Hardt's critical security binding).
  - No component parameters (`;req`, `;bs`, `;key`, `;sf`, etc.) for POC. Reject them if present; most AAuth deployments don't need them.
- **Only one signature per request**: `Signature-Input` may name the signature anything (e.g. `sig`, `aauth`). Accept a single label; error cleanly if multiple labels are present.

### 4.2 Structured Fields sub-package (`pkg/httpsig/structfields`)

Needed by both `pkg/httpsig` (Signature-Input parsing) and `pkg/sigkey` (Signature-Key parsing). Do **not** import a third-party structfields library — it's a small, well-specified grammar and we want zero-dependency footprint here.

Implement per RFC 8941:
- Types: `Item`, `InnerList`, `List`, `Dictionary`, `Params`.
- Bare item kinds: Integer, Decimal, String, Token, Byte Sequence (colon-delimited base64), Boolean.
- Parse functions: `ParseDictionary`, `ParseList`, `ParseItem`.
- Serialize functions (for tokens/tests and for the 401 `AAuth-Requirement` header).

Thorough fuzzing + round-trip tests. This will outlive the rest.

### 4.3 Verifier

```go
// pkg/httpsig
type VerifyInput struct {
    Method    string       // from ExtAuthZ httpReq.Method
    Authority string       // from ExtAuthZ httpReq.Host — MUST be passed explicitly
    Path      string       // from ExtAuthZ httpReq.Path (query included in @path per 9421)
    Headers   map[string][]string

    // Label: which signature in Signature-Input to verify. Default "sig" or the
    // single key if only one is present.
    Label string

    // Required covered components. AAuth requires at minimum:
    //   ["@method", "@authority", "@path", "signature-key"]
    RequiredComponents []string

    // Algorithm allowlist. Default: {"ed25519"} (alg=EdDSA w/ crv=Ed25519).
    AllowedAlgs []string

    // Max clock skew in both directions for `created`. Default 60s.
    MaxClockSkew time.Duration

    // Caller-supplied public key — the caller has already parsed Signature-Key
    // and resolved it (possibly via JWKS fetch) to a concrete key.
    PublicKey crypto.PublicKey
    Alg       string // "ed25519" | "ecdsa-p256"
}

type VerifyResult struct {
    Label    string
    Created  time.Time
    Covered  []string
    KeyID    string
}

func Verify(in VerifyInput) (*VerifyResult, error)
```

Flow inside `Verify`:
1. Parse `Signature-Input` into `Dictionary`. Pick the entry for `in.Label` (or the sole entry).
2. Extract `Covered` (the inner list of component identifiers) and params (`created`, `keyid`, `alg`, `nonce`, ...).
3. Verify `created` is within `MaxClockSkew` of now. Reject outside window → `ErrExpiredSignature` / `ErrFutureSignature`.
4. Enforce `RequiredComponents ⊆ Covered`. Missing `signature-key` → `ErrMissingSignatureKeyCoverage` (give this its own sentinel — it's the attack class Hardt keeps hammering on).
5. If `alg` param present, require it matches `in.Alg`. Otherwise infer from `in.Alg`.
6. Build the signature base string per RFC 9421 §2.5 from the `Covered` components and params.
7. Decode the `Signature` header's corresponding entry (Byte Sequence).
8. Verify via `crypto/ed25519` or `crypto/ecdsa`. Wrong signature → `ErrInvalidSignature`.

### 4.4 Signer (minimal)

```go
func Sign(in SignInput) (signature []byte, signatureInput string, err error)
```

Used by: resource-token minting (which is actually JWT-level signing, not HTTPSig — so the signer here is just for generating test fixtures and for the `POST /resource/token` response path that needs to sign outbound confirmations). Keep small.

### 4.5 `pkg/sigkey` — the Signature-Key header

```go
type Scheme string

const (
    SchemeHWK      Scheme = "hwk"
    SchemeJWT      Scheme = "jwt"
    SchemeJWKSURI  Scheme = "jwks_uri"
    SchemeX509     Scheme = "x509"  // stub; Parse returns ErrUnsupportedScheme
)

type Parsed struct {
    Scheme Scheme
    KeyID  string // keyid= param when present

    // HWK: inline JWK components
    HWK *jwk.Key // kty, crv, x, y, alg, ...

    // JWT: the JWT string; caller must verify before trusting `cnf.jwk`
    JWT string

    // JWKS URI
    JWKSURI string

    // X509: raw cert bytes, not yet used
    X509 []byte
}

func Parse(headerValue string) (Parsed, error)
```

Parse as an RFC 8941 Dictionary. Exactly one entry; the entry's parameters carry the scheme-specific payload (`scheme=hwk`, then JWK params; `scheme=jwt`, then `jwt="..."`; etc.). Keep the parser strict — unknown scheme → error.

### 4.6 Tests (Phase 0 acceptance)

- RFC 8941 structfields: round-trip known vectors (the spec's examples); fuzz parser against serializer output.
- RFC 9421 base construction: hand-computed base strings for AAuth-shaped requests (covered components = `@method @authority @path signature-key`).
- End-to-end: generate a request, sign with Ed25519, mutate one thing (header value, path, key), assert verify fails with the expected sentinel error. Table-driven.
- `pkg/sigkey`: parse each scheme happy-path; parse malformed inputs.

Phase 0 is done when `go test ./pkg/...` is green with meaningful coverage and no service code imports exist in `pkg/`.

---

## 5. ExtAuthZ `Check()` flow (`internal/extauthz`)

Dispatcher stays tiny:

```go
func (h *Handler) Check(ctx, req) (*CheckResponse, error) {
    attrs := req.GetAttributes()
    exts  := attrs.GetContextExtensions()
    resID, ok := exts["aauth_resource_id"]
    if !ok {
        return h.legacy.Check(ctx, req)   // preserve existing behavior
    }
    rc, ok := h.resources.ByID(resID)
    if !ok {
        return h.response.InternalError("unknown resource_id: "+resID), nil
    }
    return h.aauth.Check(ctx, rc, attrs)
}
```

`aauth.Check(ctx, rc, attrs)` is the AAuth pipeline:

1. **Extract raw signature headers** (`Signature`, `Signature-Input`, `Signature-Key`). Any missing → return `challenge.New(rc, ErrMissingSignature, nil)` — a 401 with `AAuth-Requirement: requirement=auth-token; auth-server=<url>` and a JSON body `{"error":"invalid_request"}`. No resource-token yet (we don't know the agent).

2. **Parse `Signature-Key`** via `pkg/sigkey`. Parse failure → 401 with `error=invalid_signature`.

3. **Resolve the verification key** based on scheme:
   - `hwk` → the inline key. Identity level = **pseudonymous**.
   - `jwt` → decode JWT header, branch on `typ`:
     - `agent+jwt` → find matching `agent_server` by `iss`; fetch its JWKS; verify JWT; extract `sub` (delegate), `agent` (agent server), `cnf.jwk`. Identity level = **identified**.
     - `auth+jwt` → find matching `auth_server` by `iss`; fetch its JWKS; verify JWT; verify `aud == rc.Issuer`; verify `exp`; extract `sub`, `agent`, `scope`, `txn`, `cnf.jwk`. Identity level = **authorized**.
     - Any other `typ` → `invalid_token`.
   - `jwks_uri` → require `iss` matches a known `agent_server`; fetch JWKS; select by `keyid`. Identity level = **identified**.
   - `x509` → `unsupported_scheme`.

4. **HTTPSig verify** via `pkg/httpsig.Verify` with:
   - `Authority = attrs.Request.Http.Host`
   - `RequiredComponents = ["@method","@authority","@path","signature-key"] ++ rc.AdditionalSignatureComponents`
   - `PublicKey` = resolved public key from step 3
   - `MaxClockSkew = rc.SignatureWindow`

5. **Key-binding check**: for `agent+jwt` and `auth+jwt`, the HTTPSig key MUST match `cnf.jwk` in the token (compute JWK thumbprint per RFC 7638 on both sides and compare). Mismatch → `invalid_signature`.

6. **Level gating**:
   - Pseudonymous + `rc.AllowPseudonymous == false` → 401 `require=auth-token` (now with resource-token — we have the HWK → agent identity via thumbprint).
   - Pseudonymous/Identified when the route requires authorized (future: per-route config) → 401.
   - Authorized: verify `aud`, evaluate `scope` against whatever the policy expects.

7. **Policy hook**: call `PolicyEngine.Decide(ctx, PolicyInput{...})`. See §11.

8. **Allow response** via `response.OK(rc, identity)` which adds:
   - `x-aauth-level: pseudonymous | identified | authorized`
   - `x-aauth-agent-server: <url>` (when known)
   - `x-aauth-delegate: <sub>` (when known)
   - `x-aauth-scope: <space-sep scopes>` (when authorized)
   - `x-aauth-txn: <txn>` (when present)
   - `x-aauth-jkt: <thumbprint>`
   - If `rc.StripSignatureHeaders`: remove `Signature`, `Signature-Input`, `Signature-Key` from upstream.

9. **Deny response** via `challenge.New(...)` — see §6.

Error taxonomy (sentinel types, all in `internal/aauth/errors.go`, 1:1 with the spec's verification error codes): `ErrMissingSignature`, `ErrInvalidSignature`, `ErrInvalidInput` (+ `required_input`), `ErrUnsupportedAlgorithm`, `ErrInvalidKey`, `ErrUnknownKey`, `ErrInvalidJWT`, `ErrExpiredJWT`, `ErrInvalidToken`, `ErrInsufficientScope`, `ErrUnsupportedScheme`.

---

## 6. Challenge construction (`internal/aauth/challenge.go`)

```go
type Challenge struct {
    Resource       *config.ResourceConfig
    Err            error            // used to pick error code in body
    AgentHint      *AgentHint       // nil if we couldn't identify the agent
    IssueResourceToken bool          // true when we have enough to mint one
}

func (c Challenge) Response() *pb.CheckResponse
```

`AgentHint` carries `{ Agent, AgentJKT, Scope? }` — enough to mint a resource-token bound to the caller.

The 401 response has:
- **Status**: 401
- **Header `AAuth-Requirement`**: RFC 8941 Dictionary, serialized. Members:
  - `requirement=auth-token` (Token)
  - `auth-server="<rc.AuthorizationEndpoint>"` (String)
  - `resource-token="<jwt>"` (String) — present only when `IssueResourceToken && AgentHint != nil`
- **Header `WWW-Authenticate: AAuth`** — for legacy client co-existence per spec
- **Body**: JSON, `{"error":"<code>","error_description":"..."}`

**Design note on the bootstrap 401**: when the agent sends a completely unsigned request, we have no `agent` or `agent_jkt` to bind into a resource-token. The challenge still works — it tells the agent which auth server to talk to and that an auth-token is required. The agent then signs a retry, we extract the agent's key, and we can issue a bound resource-token on the second 401 (or directly via the `/resource/token` endpoint). Track this as an open question (§15 item 1) — confirm with Dick.

Serialize `AAuth-Requirement` using `pkg/httpsig/structfields`. Don't try to hand-format it. String values are quoted; Token values are bare.

---

## 7. HTTP endpoints (`internal/httpapi`)

Mount three routes on port `listen.http`. None of these run through the ExtAuthZ filter from agentgateway's perspective.

### 7.1 `GET /.well-known/aauth-resource.json`
Lookup `rc` by `Host` header. 404 if not found. Render from config:

```json
{
  "issuer": "https://openai-api.example.com",
  "jwks_uri": "https://openai-api.example.com/.well-known/jwks.json",
  "authorization_endpoint": "https://as.example.com/authorize",
  "resource_token_endpoint": "https://openai-api.example.com/resource/token",
  "supported_scopes": ["openai.chat.read","openai.chat.write"],
  "scope_descriptions": {"openai.chat.read":"Read chat completions", ...},
  "additional_signature_components": [],
  "signature_window": 60
}
```

Headers: `Content-Type: application/json`, `Cache-Control: public, max-age=300`.

### 7.2 `GET /.well-known/jwks.json`
Public half of `rc.SigningKey` as a JWKS:

```json
{"keys":[{"kty":"OKP","crv":"Ed25519","x":"...","kid":"rsk-1","alg":"EdDSA","use":"sig"}]}
```

Cache 5m.

### 7.3 `POST /resource/token`
Accepts a signed request from an agent; returns a bound resource-token without requiring a 401 round-trip first.

- Signature is verified using the exact same pipeline as `aauth.Check` (refactor so both paths call into `aauth/verify.go`).
- Request body JSON: `{"scope":"data.read data.write","aud":"https://as.example.com"}` — `aud` optional; defaults to `rc.AuthServers[0].Issuer`.
- Policy hook applies (same interface as ExtAuthZ path).
- On success: `200 { "resource_token": "<jwt>" }`.
- On failure: same 401 shape as ExtAuthZ denial.

---

## 8. Resource-token minting (`internal/aauth/tokens.go`)

```go
type ResourceTokenClaims struct {
    Iss      string  // rc.Issuer
    Aud      string  // auth server URL
    Agent    string  // agent server URL from verified identity
    AgentJKT string  // RFC 7638 thumbprint of the presenting key
    Exp      int64   // now + 5m
    Scope    string  // space-separated; subset of rc.SupportedScopes after policy
    Txn      string  // optional
    Jti      string  // random, for replay detection at the AS
}

func MintResourceToken(rc *ResourceConfig, c ResourceTokenClaims) (string, error)
```

JOSE header: `{"typ":"resource+jwt","alg":"EdDSA","kid":"<rc.SigningKey.Kid>"}`.

Also implement `ParseAndVerifyAgentToken` and `ParseAndVerifyAuthToken` here — callers pass the resolved JWKS, we return typed claim structs.

JWT note: use a tiny in-repo JWT helper (sign/verify + base64url). Don't pull `golang-jwt` or equivalent for a core-crypto concern this small, especially since we already have Ed25519 wired via `pkg/httpsig`. Keep the dependency surface thin.

---

## 9. JWKS fetching (`internal/jwksfetch`)

```go
type Client interface {
    Get(ctx context.Context, uri string) (jwk.Set, error)
    // Called when Verify fails with a kid miss — one-shot refresh then retry.
    Invalidate(uri string)
}
```

- `http.Client` with a 5s timeout, 1 MiB response cap.
- **URI allowlist**: the fetcher is constructed with the union of `jwks_uri` values from every resource's `auth_servers` + `agent_servers` in config. Any other URI → immediate error. This closes off SSRF and stops foot-gun "follow `iss` anywhere" behavior.
- TTL cache: success `jwks_cache.success_ttl`, errors `jwks_cache.error_ttl` (negative cache prevents hammering a flaky JWKS on signature storms).
- On `kid` miss: `Invalidate` + re-fetch once, then retry verification. Handles key rotation.

---

## 10. Identity extraction → upstream headers (`internal/aauth/identity.go`)

Single function: `func ToUpstreamHeaders(id Identity) []*pb.HeaderValueOption`. Tested in isolation because this is the contract between us and the backend service. Stable header names matter; write them down in a README next to the package.

---

## 11. Policy interface (`internal/policy`)

```go
type Decision struct {
    Allow   bool
    Reason  string            // logged, not returned to client
    Headers []Header          // added to upstream on allow; ignored on deny
    Denial  *DenialDetails    // populated on deny: status code (usually 401 or 403), error code
}

type PolicyInput struct {
    Resource     string                 // rc.Issuer
    Method, Path, Host string
    Identity     Identity
    Headers      map[string]string
    ContextExt   map[string]string
}

type Engine interface {
    Name() string
    Decide(ctx context.Context, in PolicyInput) (Decision, error)
}
```

Default implementation in `policy/default.go`: always `Decision{Allow: true}`. The point of the interface is to give downstream users a single hook to plug in OPA/OpenFGA/custom Go. Configuration says `policy.name: default` for POC.

The policy call happens **after** AAuth verification succeeds. AAuth validation is always mandatory — the policy layer cannot weaken protocol correctness.

---

## 12. Phased delivery

### Phase 0 — Library foundation
**Deliverables**
- `pkg/httpsig/structfields` with `ParseDictionary` / `ParseList` / `ParseItem` + serialize.
- `pkg/httpsig` with `Verify`, `Sign`, Ed25519 + P-256, components `@method @authority @path signature-key` + header fields.
- `pkg/sigkey` with `Parse` for `hwk`, `jwt`, `jwks_uri`; stub `x509`.
- Unit + table tests, vectors under `testdata/vectors/`.

**Acceptance**
- `go test ./pkg/...` green. No imports from `internal/` into `pkg/`.
- Hand-crafted AAuth-style signed request verifies; mutating method/path/authority/any signed header breaks verification with the right error.
- `signature-key` coverage absence triggers `ErrMissingSignatureKeyCoverage`.

### Phase 1 — Pseudonymous HWK over ExtAuthZ
**Deliverables**
- `internal/config` + `internal/resource/registry`.
- `internal/extauthz/handler.go` dispatcher; legacy code path preserved.
- `internal/extauthz/aauth.go` supports only `scheme=hwk`.
- `internal/aauth/challenge.go` returns 401 with `AAuth-Requirement: requirement=auth-token; auth-server="..."` (no resource-token yet).
- `internal/policy/default.go` allow-all engine; wired.

**Acceptance**
- Test harness with an in-process gRPC client: unsigned request → 401 with correct header; HWK-signed request → OK.
- agentgateway deployed with a route using `context_extensions: { aauth_resource_id: "<id>" }`; unsigned curl → 401, signed request via the Python AAuth client → passes to backend.

### Phase 2 — Resource tokens + metadata endpoints
**Deliverables**
- `internal/resource/keys.go` loads Ed25519 private keys.
- `internal/aauth/tokens.go` mints resource-tokens (JOSE + JWT helpers).
- `internal/httpapi` serves `/.well-known/aauth-resource.json` and `/.well-known/jwks.json`.
- `challenge.New` now embeds a `resource-token=` parameter when the request is signed (identity → `agent_jkt`).

**Acceptance**
- `curl -H "Host: openai-api.example.com" http://svc:8080/.well-known/aauth-resource.json` → correct JSON.
- 401 response carries a resource-token; decoding it shows correct `iss`, `aud`, `agent_jkt`, `exp`.
- JWKS at `/jwks.json` verifies the resource-token signature.

### Phase 3 — Identified level (agent tokens + jwks_uri)
**Deliverables**
- `internal/jwksfetch` (cache + allowlist + kid-miss refresh).
- `pkg/sigkey` `jwks_uri` scheme fully wired.
- `agent+jwt` verification path in `aauth/tokens.go` and `aauth/verify.go`.
- `cnf.jwk` ↔ HTTPSig key binding enforced.

**Acceptance**
- Against a fake agent-server (test-only JWKS hosted by the harness), an agent-token-bearing request verifies; substituting any field (wrong `cnf.jwk`, expired token, wrong issuer) fails with the matched sentinel.
- Upstream headers include `x-aauth-agent-server` and `x-aauth-delegate`.

### Phase 4 — Authorized level (auth tokens)
**Deliverables**
- `auth+jwt` path. `aud` check against `rc.Issuer`. `scope` / `txn` extraction.
- Upstream headers include `x-aauth-scope`, `x-aauth-txn`.
- Scope check hook for future route-level requirements (config field reserved, not wired yet).

**Acceptance**
- End-to-end: test harness stands up a fake AS (issues Ed25519-signed auth+jwt), agent obtains one and calls the resource, we verify it, downstream sees verified identity.

### Phase 5 — `/resource/token` endpoint
**Deliverables**
- `internal/httpapi/resource_token.go` + shared verification path with ExtAuthZ via `aauth/verify.go`.

**Acceptance**
- Agent can `POST /resource/token` with a signed request and scope params, receive a resource-token without first triggering a 401.

### Phase 6 — Hardening
**Deliverables**
- Structured JSON logs per decision (resource_id, level, scheme, result, latency).
- Prometheus metrics: `aauth_check_total{resource,level,result}`, `aauth_jwks_fetch_total{uri,result}`, latency histograms.
- Config hot-reload on SIGHUP (optional).
- Thorough integration tests, docker-compose demo stack (agentgateway + this service + fake AS + dummy backend + a shell-scripted agent).

---

## 13. Test strategy

### Unit
- `pkg/httpsig` + `pkg/sigkey`: as above.
- `internal/aauth/tokens`: mint → parse → verify roundtrip; mutate each claim and assert rejection.
- `internal/jwksfetch`: TTL honored; negative cache suppresses repeat fetches; kid-miss triggers exactly one refresh.
- `internal/aauth/challenge`: `AAuth-Requirement` serialization matches expected byte string; resource-token embedded when hint provided.

### Integration (in-process, no Envoy/agw needed)
Drive the gRPC handler with a table of CheckRequest fixtures:

| # | Scenario | Expected |
|---|----------|----------|
| 1 | No signature headers | 401, `invalid_request`, AAuth-Requirement present, no resource-token |
| 2 | Valid HWK sig, policy=default | OK, upstream headers stamped |
| 3 | HWK sig, `signature-key` NOT covered | 401, `invalid_signature` |
| 4 | HWK sig, `created` 90s old | 401, `invalid_signature` |
| 5 | HWK sig, wrong algorithm declared | 401, `unsupported_algorithm` |
| 6 | `agent+jwt`, `cnf.jwk` doesn't match HTTPSig key | 401, `invalid_signature` |
| 7 | `auth+jwt`, `aud` mismatch | 401, `invalid_token` |
| 8 | `auth+jwt` expired | 401, `invalid_token` |
| 9 | `jwks_uri` scheme, `iss` not on allowlist | 401, `invalid_key` |
| 10 | `x509` scheme | 401, `unsupported_scheme` |

### HTTP endpoint tests
- Metadata render by Host; 404 for unknown Host.
- JWKS matches the loaded signing key.
- `/resource/token` mirrors the verification table.

### End-to-end (Phase 6)
docker-compose with agentgateway, aauth-service, fake AS, dummy backend. Shell script drives a Python agent through all three identity levels and asserts the backend received the expected `x-aauth-*` headers.

---

## 14. Key implementation details worth calling out

- **Use `attrs.Request.Http.Host` verbatim as `@authority`.** Agentgateway forwards the external Host explicitly (confirmed). Don't reconstruct from other fields.
- **Use `attrs.Request.Http.Path` verbatim as `@path`.** Per RFC 9421 this is the raw path-and-query.
- **Never trust `attrs.Request.Http.Scheme` for anything security-relevant.** Not in the signature base.
- **Header casing**: the ExtAuthZ `Headers` map keys are lowercase. RFC 9421 canonicalizes via lowercasing too, so this is fine, but assert on it in a test.
- **`Signature-Key` is a header, and it's included in the signed content** — this is the attack-class Hardt keeps emphasizing. The verifier must reject any signature that doesn't cover `signature-key`. Make this its own sentinel error.
- **Don't log `Signature-Key` values at INFO**. Private key material doesn't appear there (it's public), but JWT values that embed claims the agent considers sensitive might. DEBUG only.
- **Keep `pkg/` free of `internal/` imports.** Enforced by design — makes the libraries independently extractable if you want to contribute them upstream.
- **Error responses must be stable**: the body JSON shape (`{"error": "...", "error_description": "..."}`) and the `AAuth-Requirement` Structured Dictionary serialization are part of the contract with AAuth-aware agents.

---

## 15. Open questions (track as GitHub issues upstream once clarified)

1. **Bootstrap 401 shape**: when the agent has sent no `Signature-Key`, is it correct to omit `resource-token` from the 401 and let the agent sign-then-retry to get one? Or should the resource issue an unbound resource-token? Recommend the former; get spec clarification.
2. **`@authority` canonicalization behind reverse proxies**: worth spec guidance. Which Host wins — the external one the agent used or the internal one the backend sees? Canonical answer is the external; document it.
3. **Per-path `additional_signature_components`**: `content-digest` on `POST` but not `GET` is a common shape. Current metadata doc is resource-wide. Worth raising if you add content-digest support.
4. **Replay defense for HWK signatures**: `created` window prevents most replay, but there's no `nonce` or server-side seen-cache in the current plan. Fine for POC; mention in security notes.

---

## 16. Getting started checklist for Claude Code

When starting Phase 0:
1. Initialize module paths: current repo uses `policy_engine/gen/proto`; don't disturb that. New packages go under `github.com/christian-posta/extauth-policy-engine/pkg/...` and `.../internal/...`.
2. Add `testdata/` with one known Ed25519 key pair used across tests.
3. Write `structfields` first (it unblocks everything) — parser before serializer, with round-trip tests.
4. Write `pkg/httpsig/base.go` next — the signature base construction is the most error-prone piece and easiest to fix before algorithms get plumbed in.
5. Only after `go test ./pkg/...` is solid do we refactor `main.go` into `cmd/server/main.go`.

When starting Phase 1:
1. Move the existing inline-Go rules into `internal/extauthz/legacy.go` **unchanged** so current behavior is preserved on routes without `aauth_resource_id`.
2. Load config from a flag: `--config /etc/aauth/config.yaml`.
3. First milestone: an unsigned request to an AAuth route returns a 401 with a valid `AAuth-Requirement` header and nothing else changes about the service.
