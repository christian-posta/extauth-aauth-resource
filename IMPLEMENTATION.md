# Implementation Notes

## Deviations from the Plan (`aauth-extauthz-plan.md`)

The plan was written before the AAuth spec draft was studied closely. Several things changed during implementation:

### Signature-Key header format

The plan described the scheme as a `scheme=` parameter (e.g. `sig=?1;scheme="hwk";...`). The actual spec format is an RFC 8941 Dictionary where the **entry value is the scheme Token**:

```
# Spec-compliant (what this service parses)
sig=hwk;kty="OKP";crv="Ed25519";x="..."
sig=jwt;jwt="<token>"
sig=jwks_uri;uri="https://...";keyid="kid"

# Old format (no longer supported)
sig=?1;scheme="hwk";kty="OKP";...
```

### JWT typ values

| Purpose | Plan said | Spec / implementation |
|---------|-----------|----------------------|
| Agent token | `agent+jwt` | `aa-agent+jwt` |
| Auth token | `auth+jwt` | `aa-auth+jwt` |
| Resource token | `resource+jwt` | `aa-resource+jwt` |

### `dwk` claim

All AAuth JWT types carry a `dwk` claim naming the well-known document for JWKS discovery:
- Agent tokens: `dwk = "aauth-agent.json"`
- Auth tokens: `dwk = "aauth-access.json"` or `"aauth-person.json"`
- Resource tokens: `dwk = "aauth-resource.json"` (auto-set by `MintResourceToken`)

### JWKS discovery

The plan used the config-specified `jwks_uri` for all key lookups. The `jwt` scheme now uses spec-defined discovery: `{iss}/.well-known/{dwk}`. The `jwks_uri` config field is still used for the `jwks_uri` Signature-Key scheme and is kept in the JWKS allowlist for backwards compatibility.

### `act` claim (RFC 8693)

Auth tokens (`aa-auth+jwt`) must carry an `act` claim where `act.sub` equals the RFC 7638 JWK thumbprint of `cnf.jwk`. This is the spec's mechanism for binding the auth token to the agent that will use it.

### `jws.WithInferAlgorithmFromKey`

When verifying JWTs with `lestrrat-go/jwx/v2`, the `jws.WithInferAlgorithmFromKey(true)` option must be passed when the JWKS keys don't have an explicit `alg` field set.

### agentgateway Host header

agentgateway strips the port before putting the `Host` value into the CheckRequest `host` field. A request to `http://host:3001/` arrives at the service as `host = "localhost"`, not `"localhost:3001"`. The resource config's `hosts` list must include the bare hostname and the signing client must use the bare hostname as `@authority`.

## Package structure

The protocol logic lives in a standalone library (`github.com/christian-posta/aauth-go`)
with no gRPC or Envoy dependencies. This service is the ExtAuthZ integration layer on top of it.

```
cmd/
  server/           main entry point (gRPC + HTTP servers)
  sign-request/     CLI tool: generates a signed curl command (hwk scheme)
  debug-extauthz/   gRPC inspector: dumps every CheckRequest and returns OK
  integration-test/ direct gRPC integration test

internal/
  aauth/            thin wrappers / adapters over the aauth-go library
    verify.go       orchestrates sigkey parse + httpsig verify + token checks
    tokens.go       ResourceTokenClaims struct + MintResourceToken
    tokens_jwt.go   ParseAndVerifyAgentToken (aa-agent+jwt)
    tokens_auth.go  ParseAndVerifyAuthToken  (aa-auth+jwt)
    challenge.go    builds AAuth-Requirement 401 responses (returns pb.CheckResponse)
    identity.go     Identity struct + ToUpstreamHeaders (returns pb.HeaderValueOption)
    errors.go       sentinel error values
  config/           YAML config types + LoadConfig
  extauthz/         gRPC Check() handler + AAuthHandler
  httpapi/          HTTP server (metadata, JWKS, resource-token endpoints)
  jwksfetch/        JWKS HTTP client with URI allowlist + discovery URLs + Prometheus metrics
  policy/           Engine interface + default allow-all implementation
  resource/         Registry (ByID / ByHost) + key loading

pkg/
  httpsig/          RFC 9421 — Sign + Verify; structfields sub-package
  sigkey/           Signature-Key header parser (hwk / jwt / jwks_uri)
```

### What belongs in aauth-go vs here

| Concern | Library (`aauth-go`) | Service (this repo) |
|---|---|---|
| Signature verification | Yes | No |
| JWT token validation | Yes | No |
| Challenge response building | Yes (generic struct) | Adapts to pb.CheckResponse |
| Identity extraction | Yes (`map[string]string`) | Adapts to pb.HeaderValueOption |
| JWKS fetching | Yes (no metrics) | Wraps with Prometheus metrics |
| Config | Library-own `Config` type | YAML + service-level fields |
| gRPC / ExtAuthZ | No | Yes |
| HTTP API (JWKS, metadata) | No | Yes |
| Policy engine | No | Yes |
