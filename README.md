# AAuth Resource-Side ExtAuthZ Service

A multi-tenant AAuth resource-side service implemented in Go. Protect backend APIs with the AAuth protocol by deploying it behind [AgentGateway](https://github.com/agentgateway/agentgateway/) or Envoy proxy using the [ExtAuthZ](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/http/ext_authz/v3/ext_authz.proto) protocol.

Implements:
- [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421) HTTP Message Signatures
- [RFC 8941](https://www.rfc-editor.org/rfc/rfc8941) Structured Field Values
- [Dick Hardt's AAuth protocol draft](https://github.com/dickhardt/AAuth) — `Signature-Key` schemes `hwk`, `jwt`, `jwks_uri`

> **Looking for the standalone Go library?** The core AAuth protocol logic (signature verification, JWT token validation, challenge building) is also available as a transport-agnostic library with no gRPC or Envoy dependencies:
> [`github.com/christian-posta/aauth-go-library`](https://github.com/christian-posta/aauth-go-library)

---

## Getting Started

| Goal | Guide |
|------|-------|
| **End-to-end hello world** — run the extauth service + agentgateway + a Go agent client that proves identity at the `identified` level (`jwks_uri` and `aa-agent+jwt` schemes) | [docs/hello-world.md](docs/hello-world.md) |
| **Mode 3 (authorized)** — three-party flow where an Access Server issues an `aa-auth+jwt` after the agent exchanges a resource-token | [docs/mode3.md](docs/mode3.md) |
| **Reference config** — every supported YAML option with inline comments | [aauth-config.example.yaml](aauth-config.example.yaml) |

```bash
# Build everything, then follow docs/hello-world.md
make build build-agent-client
```

Prerequisites: Go 1.24+, [`agentgateway`](https://github.com/agentgateway/agentgateway) on `$PATH`, free ports `3001 7070 8080 9099`, and outbound HTTPS if you use the default `test-agw.yaml` upstream ([httpbin.org](https://httpbin.org/)).

---

## Features

- **Multi-Tenant**: A single deployment can protect multiple distinct APIs, identified either by `aauth_resource_id` in agentgateway's `contextExtensions` or by Host header.
- **Dual-Listener Architecture**:
  - `gRPC :7070` — Envoy/agentgateway ExtAuthZ endpoint
  - `HTTP :8080` — Binds `/.well-known/aauth-resource.json`, `/.well-known/jwks.json`, and `/resource/token` (with `test-agw.yaml`, call these on **`http://localhost:3001`** so traffic goes through agentgateway; the gateway forwards to `:8080` without ExtAuthZ)
- **Identity Levels**: `pseudonymous` (inline bare key), `identified` (agent+jwt or jwks_uri), `authorized` (auth+jwt)
- **AAuth Challenges**: Generates `AAuth-Requirement` 401 responses; automatically mints and embeds `resource-token`s when the agent has provided signing-key material
- **JWKS Discovery**: Fetches agent/auth server keys via `{issuer}/.well-known/{dwk}` per the AAuth spec
- **ExtAuthZ dynamic metadata**: On allow, the gRPC `CheckResponse` includes level-aware `dynamic_metadata` for downstream CEL rules in AgentGateway

## Access Modes

Resources can now be configured independently for either [Identity Access Mode (Mode 1)](https://explorer.aauth.dev/access/identity-based) or [PS-asserted Access Mode (Mode 3)](https://explorer.aauth.dev/access/ps-asserted):

- `access.require: identity` keeps the existing Mode 1 behavior. A valid `aa-agent+jwt`, `jwks_uri`, or allowed `hwk` request is enough to pass auth.
- `access.require: auth-token` enables Mode 3. A valid Mode 1 request is challenged with `AAuth-Requirement: requirement=auth-token; resource-token="..."` until the caller retries with an `aa-auth+jwt`.

If `access.require` is omitted, it defaults to `identity`, so existing Mode 1 configurations continue to work unchanged.

## How to Test End-to-End

The following walks through running the service locally with agentgateway.

### Prerequisites

- Go 1.24+
- `agentgateway` binary in your `$PATH`
- `jq` (optional, for pretty-printing JSON)

---

### 1. Build

```bash
# Build the AAuth service
go build -o aauth-service ./cmd/server
# Or via Makefile:
make build

# Build the signing helper (used in tests below)
go build -o sign-request ./cmd/sign-request
# Or via Makefile:
make build-sign-request
```

---

### 2. Generate a Resource Signing Key

The service signs resource-tokens with an Ed25519 key. Generate one:

```bash
go run ./cmd/generate-key
# Or via Makefile:
make generate-key
# Creates: resource_key.pem  (private key, PKCS8 PEM)
#          resource_pub.pem  (public key, PKIX PEM)
```

---

### 3. Create `aauth-config.yaml`

The file `aauth-config.example.yaml` in the repository root lists every supported option with inline comments (including `allowed_signature_key_schemes` and `allowed_jwt_types`).

This config defines a single protected resource (`backend-api`) that allows pseudonymous access:

```yaml
listen:
  grpc: ":7070"
  http: ":8080"

jwks_cache:
  success_ttl: 5m
  error_ttl: 30s
  max_entries: 1000

resources:
  - id: backend-api
    issuer: http://localhost:3001
    client_name: Example Backend API
    hosts:
      - localhost:3001      # Host after agentgateway urlRewrite (see §4 / test-agw.yaml)
    signing_key:
      kid: rsk-1
      alg: EdDSA
      private_key_file: resource_key.pem
    signature_window: 60s
    allow_pseudonymous: true   # accept hwk-scheme bare keys
    strip_signature_headers: true
    policy:
      name: default
```


---

### 4. Create `test-agw.yaml`

Configure agentgateway to proxy plain HTTP to an upstream host and delegate authorization to this service. The checked-in `test-agw.yaml` also routes `/.well-known/*` and `/resource/*` to this service's HTTP listener **without** ExtAuthZ, and uses `urlRewrite.authority` so the upstream sees `Host: localhost:3001` (same idea as `aauth-full-demo/agentgateway/config-policy.yaml`). That keeps `hosts` in `aauth-config.yaml` to a single value matching `issuer`.

```yaml
# yaml-language-server: $schema=https://agentgateway.dev/schema/config
binds:
- port: 3001
  listeners:
  - protocol: HTTP
    routes:
    - name: aauth-dwk
      matches:
      - path:
          pathPrefix: /.well-known/
      policies:
        urlRewrite:
          authority:
            full: localhost:3001
      backends:
      - host: "localhost:8080"
    - name: aauth-resource-http
      matches:
      - path:
          pathPrefix: /resource/
      policies:
        urlRewrite:
          authority:
            full: localhost:3001
      backends:
      - host: "localhost:8080"
    - policies:
        extAuthz:
          host: "localhost:7070"
          protocol:
            grpc:
              context:
                aauth_resource_id: "backend-api"   # tells the service which resource config to use
      backends:
      - host: "httpbin.org:443"
        policies:
          backendTLS: {}
```

Swap `httpbin.org:443` for any `host:port` you control (for example a local [httpbin](https://hub.docker.com/r/kennethreitz/httpbin) container on `127.0.0.1:8000` without `backendTLS`).

Without `context.aauth_resource_id` the service falls back to Host-based resource lookup, which also works as long as the `hosts` list in the config includes the incoming host. Requests that do not map to a configured resource are denied.

---

### 5. Start Both Services

**Terminal 1** — AAuth service:
```bash
export AAUTH_CONFIG=aauth-config.yaml
./aauth-service
```

Expected output:
```
Policy Engine starting on :7070
This service implements the Envoy ext_authz protocol
Starting HTTP API on :8080
```

**Terminal 2** — agentgateway:
```bash
agentgateway -f test-agw.yaml
```

---

### 6. Test 1: Unsigned Request → 401 Challenge

```bash
curl -i "http://localhost:3001/get" -H "Host: localhost:3001"
```

Expected:
```http
HTTP/1.1 401 Unauthorized
aauth-requirement: requirement=auth-token
www-authenticate: AAuth
content-type: application/json

{"error":"missing_signature"}
```

The `AAuth-Requirement` header tells the agent that a signed request (or auth token) is required.

---

### 7. Test 2: Pseudonymous Signed Request → Passes Auth

The `cmd/sign-request` tool generates a fresh Ed25519 keypair, builds a valid RFC 9421 HTTP Message Signature, and prints the `curl` command:

```bash
./sign-request -method GET -authority localhost:3001 -path /get
```

Which prints a `curl` command like this:

```bash
curl -si -X GET 'http://localhost:3001/get' \
  -H 'Content-Type: application/json' \
  -H 'signature-key: sig=hwk;kty="OKP";crv="Ed25519";x="OguDVxeWMJpR03m4peUnFUoG8JSApnzxUhelgXl9hhM"' \
  -H 'signature-input: sig=("@method" "@authority" "@path" "signature-key");created=1778637537;alg="ed25519";keyid="sig"' \
  -H 'signature: sig=:dMCBMoZ/1pZkyJzbIVUJPYUhoz2rSknT3Ogwx6FhJ1KE0k2pAfpaQrBtynpHpzGkurVR2W5nLXeDAPm23wfTDg==:'

```

If you run that curl, you should see a response like this:

```http
HTTP/1.1 200 OK
date: Wed, 13 May 2026 01:59:03 GMT
content-type: application/json
content-length: 402
server: gunicorn/19.9.0
access-control-allow-origin: *
access-control-allow-credentials: true

{
  "args": {},
  "headers": {
    "Accept": "*/*",
    "Content-Type": "application/json",
    "Host": "httpbin.org",
    "User-Agent": "curl/8.7.1",
    "X-Aauth-Jkt": "L8gISWEsmljmLlBHuzIESHwGEeLYWdu-P6WkAnF5NW0",
    "X-Aauth-Level": "pseudonymous",
    "X-Amzn-Trace-Id": "Root=1-6a03dae7-3036405c1750377c78a096c2"
  },
  "origin": "166.194.143.125",
  "url": "https://httpbin.org/get"
}

```
The body is httpbin’s `/get` echo payload (your request URL, headers, and origin). A **non-401** response proves ExtAuthZ allowed the request and the gateway reached the upstream.

---

### 8. Test 3: Inspect What the Service Extracted

Check the structured decision log in the AAuth service terminal:

```json
{"time":"...","resource_id":"backend-api","level":"pseudonymous","result":"allowed","latency_ms":0}
```

Upstream headers added by the service (visible to httpbin and echoed in the JSON `headers` object when you call `/get`):
- `x-aauth-level: pseudonymous`
- `x-aauth-jkt: <RFC 7638 SHA-256 thumbprint of the signing key>`

---

### 9. Test 4: Resource JWKS and Metadata Endpoints

Use agentgateway (`test-agw.yaml`) so discovery matches the same origin clients use for protected routes:

```bash
# Resource metadata (tells agents where to get auth tokens and resource tokens)
curl -s http://localhost:3001/.well-known/aauth-resource.json | jq .
```

```json
{
  "issuer": "http://localhost:3001",
  "jwks_uri": "http://localhost:3001/.well-known/jwks.json",
  "authorization_endpoint": "http://localhost:3001/resource/token",
  "client_name": "Example Backend API",
  "signature_window": 60,
  "supported_scopes": null
}
```

If a resource does not have a usable signing key, the metadata omits `authorization_endpoint` instead of advertising a broken token-minting endpoint.

```bash
# JWKS (public key used to verify resource-tokens the service mints)
curl -s http://localhost:3001/.well-known/jwks.json | jq .
```

```json
{
  "keys": [{
    "kty": "OKP",
    "crv": "Ed25519",
    "kid": "rsk-1",
    "alg": "EdDSA",
    "use": "sig",
    "x": "<base64url-encoded-public-key>"
  }]
}
```

---

## Signature-Key Format

The `Signature-Key` header follows the AAuth spec (RFC 8941 Dictionary where the dict entry **value** is the scheme Token):

| Scheme | Format | When to use |
|--------|--------|-------------|
| `hwk` | `sig=hwk;kty="OKP";crv="Ed25519";x="<base64url>"` | Pseudonymous bare key |
| `jwt` | `sig=jwt;jwt="<aa-agent+jwt or aa-auth+jwt>"` | Agent token or auth token |
| `jwks_uri` | `sig=jwks_uri;id="<issuer>";dwk="<well-known-doc>";kid="<kid>"` | Agent server metadata discovery + JWKS lookup |

> **Old format** (`sig=?1;scheme="hwk";...`) is no longer supported — the scheme is the dict entry value, not a `scheme=` parameter.

---

## Agentgateway Integration Notes

1. **Context extensions**: the `aauth_resource_id` extension maps a route directly to a resource config:
   ```yaml
   extAuthz:
     host: "localhost:7070"
     protocol:
       grpc:
         context:
           aauth_resource_id: "my-resource"
   ```
   Without this, the service falls back to Host-header based lookup.

2. **Strip signature headers**: set `strip_signature_headers: true` in the resource config to remove `Signature`, `Signature-Input`, and `Signature-Key` before the request reaches the backend.

---

## Upstream Headers

On a successful auth check the service adds these headers to the upstream request:

| Header | When present | Content |
|--------|-------------|---------|
| `x-aauth-level` | Always | `pseudonymous`, `identified`, or `authorized` |
| `x-aauth-jkt` | Always | RFC 7638 SHA-256 JWK thumbprint of the signing key |
| `x-aauth-agent-server` | `identified`/`authorized` | Agent server issuer for identity tokens/discovery, or authorized agent identifier from an auth token |
| `x-aauth-delegate` | `identified`/`authorized` | `sub` claim from the agent/auth token |
| `x-aauth-scope` | `authorized` | Space-separated granted scopes |
| `x-aauth-txn` | `authorized`, if present | Transaction ID from the auth token |

---

## ExtAuthZ dynamic metadata and CEL (AgentGateway)

This service speaks **gRPC** ext_authz (Envoy-compatible `Check` / `CheckResponse`). When a request is allowed after verifying AAuth identity material, the response sets **`CheckResponse.dynamic_metadata`** as a `google.protobuf.Struct`. AgentGateway exposes that object to local authorization (CEL) as the **`extauthz`** variable, so you can enforce route-level rules without re-parsing identity headers or JWTs downstream.

Dynamic metadata is level-aware. `authorized` requests include auth-token details such as `agent`, `scope`, `act`, and `sub`. `identified` requests include identity-token or discovery details such as `agent_server`, `issuer`, and `sub` when available. `pseudonymous` requests intentionally expose only low-trust key identity details.

| Key | Type | Meaning |
|-----|------|---------|
| `level` | string | Identity level: `pseudonymous`, `identified`, or `authorized` |
| `scheme` | string | `Signature-Key` scheme: `hwk`, `jwks_uri`, or `jwt` |
| `token_type` | string | JWT `typ` for `jwt` scheme requests, such as `aa-agent+jwt` or `aa-auth+jwt` |
| `issuer` | string | JWT `iss`, or `jwks_uri` discovery `id` |
| `key_id` | string | `kid` from `Signature-Key` or JWT header when known |
| `jkt` | string | RFC 7638 SHA-256 thumbprint of the signing or bound key |
| `agent_server` | string | Agent server issuer for `identified` requests (`aa-agent+jwt` or `jwks_uri`) |
| `agent` | string | Agent identifier from the `aa-auth+jwt` `agent` claim |
| `scope` | string | OAuth-style scope string from the `aa-auth+jwt` `scope` claim |
| `txn` | string | Transaction ID from the `aa-auth+jwt` `txn` claim |
| `act` | object | RFC 8693 actor from `aa-auth+jwt`; use `act.sub` in CEL |
| `sub` | string | JWT subject when present (`aa-agent+jwt` or `aa-auth+jwt`) |

Example CEL rules (exact builtins and string helpers depend on your AgentGateway / CEL version):

```yaml
authorization:
  rules:
    # Require a non-empty delegate subject from a JWT-backed request
    - "extauthz.sub != ''"

    # Restrict to a known authorized agent URI
    - "extauthz.agent == 'aauth:local@agents.example.com'"

    # Allow identity-only requests from a known agent server
    - "extauthz.level == 'identified' && extauthz.agent_server == 'https://agents.example.com'"

    # Treat pseudonymous requests as key-bound only
    - "extauthz.level == 'pseudonymous' && extauthz.jkt != ''"

    # Scope is a single string from the JWT (often space-separated OAuth scopes); exact match:
    - "extauthz.scope == 'read:data write:data'"

    # Actor must match agent (token verification already enforces act.sub == agent; optional defense in depth)
    - "extauthz.act.sub == extauthz.agent"

    # Combine claims
    - "extauthz.sub != '' && extauthz.scope != ''"
```

For partial scope checks (for example, requiring `read:data` inside a longer `scope` string), use whatever string or regex helpers your gateway documents for CEL, or normalize scopes in your auth server.

If your gateway maps HTTP ext_authz responses into metadata instead, configure the **`metadata`** block on the HTTP protocol; this repository’s gRPC server populates **`dynamic_metadata`** directly on `CheckResponse`, which is the native Envoy path for gRPC ext_authz.

---

## Observability

Prometheus metrics at `GET http://localhost:8080/metrics`:
- `aauth_check_total{resource,level,result}` — hit rates, identity levels, error classes
- `aauth_check_duration_seconds{resource,result}` — per-decision latency histogram
- `aauth_jwks_fetch_total{uri,result}` — JWKS fetch cache hit/miss rates

Structured JSON decision log on stdout for every check:
```json
{"time":"...","resource_id":"backend-api","level":"pseudonymous","result":"allowed","latency_ms":0}
```

---

## Tools

| Tool | Purpose |
|------|---------|
| `go run ./cmd/generate-key` or `make generate-key` | Generate an Ed25519 keypair as PEM files |
| `go run ./cmd/sign-request` or `make build-sign-request` | Generate a signed `curl` command for testing (pseudonymous `hwk` scheme) |
| `go run ./cmd/agent-client` or `make build-agent-client` | All-in-one demo agent client; hosts well-known endpoints and signs requests in `jwks_uri` or `aa-agent+jwt` mode (see [docs/hello-world.md](docs/hello-world.md)) |
| `go run ./cmd/debug-extauthz` | gRPC inspector that dumps every CheckRequest (listens on `:7071`) |
| `go run ./cmd/integration-test` | Direct gRPC integration test against a running service |
