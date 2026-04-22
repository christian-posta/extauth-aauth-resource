# AAuth Resource-Side ExtAuthZ Service

A multi-tenant AAuth resource-side service implemented in Go. Protect backend APIs with the AAuth protocol by deploying it behind an Envoy proxy or AgentGateway using the ExtAuthZ gRPC protocol.

Implements:
- [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421) HTTP Message Signatures
- [RFC 8941](https://www.rfc-editor.org/rfc/rfc8941) Structured Field Values
- [Dick Hardt's AAuth protocol draft](https://github.com/dickhardt/AAuth) — `Signature-Key` schemes `hwk`, `jwt`, `jwks_uri`

> **Looking for the standalone Go library?** The core AAuth protocol logic (signature verification, JWT token validation, challenge building) is also available as a transport-agnostic library with no gRPC or Envoy dependencies:
> [`github.com/christian-posta/aauth-go`](https://github.com/christian-posta/aauth-go)

## Features

- **Multi-Tenant**: A single deployment can protect multiple distinct APIs, identified either by `aauth_resource_id` in agentgateway's `contextExtensions` or by Host header.
- **Dual-Listener Architecture**:
  - `gRPC :7070` — Envoy/agentgateway ExtAuthZ endpoint
  - `HTTP :8080` — Serves `/.well-known/aauth-resource.json`, `/.well-known/jwks.json`, and `/resource/token`
- **Identity Levels**: `pseudonymous` (inline bare key), `identified` (agent+jwt or jwks_uri), `authorized` (auth+jwt)
- **AAuth Challenges**: Generates `AAuth-Requirement` 401 responses; automatically mints and embeds `resource-token`s when the agent has provided signing-key material
- **JWKS Discovery**: Fetches agent/auth server keys via `{issuer}/.well-known/{dwk}` per the AAuth spec

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

This config defines a single protected resource (`mcp-api`) that allows pseudonymous access:

```yaml
listen:
  grpc: ":7070"
  http: ":8080"

jwks_cache:
  success_ttl: 5m
  error_ttl: 30s
  max_entries: 1000

resources:
  - id: mcp-api
    issuer: http://localhost:8080
    hosts:
      - localhost:8080
      - localhost:3001
      - localhost           # agentgateway strips the port — include the bare hostname
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

> **Note on `hosts`**: agentgateway strips the port number before putting the `Host` value into the CheckRequest (e.g. `localhost:3001` becomes `localhost`). You must include the bare hostname alongside any `host:port` forms so the registry lookup succeeds.

---

### 4. Create `agw-config.yaml`

Configure agentgateway to proxy to an MCP backend and delegate all authorization decisions to our service:

```yaml
binds:
- port: 3001
  listeners:
  - routes:
    - policies:
        extAuthz:
          host: "localhost:7070"
          protocol:
            grpc:
              context:
                aauth_resource_id: "mcp-api"   # tells the service which resource config to use
      backends:
      - mcp:
          targets:
          - name: everything
            stdio:
              cmd: npx
              args: ["-y", "@modelcontextprotocol/server-everything"]
```

Without `context.aauth_resource_id` the service falls back to Host-based resource lookup, which also works as long as the `hosts` list in the config includes the incoming host.

---

### 5. Start Both Services

**Terminal 1** — AAuth service:
```bash
export AAUTH_CONFIG=aauth-config.yaml
./aauth-service --port 7070
```

Expected output:
```
Policy Engine starting on port 7070
This service implements the Envoy ext_authz protocol
Starting HTTP API on :8080
```

**Terminal 2** — agentgateway:
```bash
agentgateway -f agw-config.yaml
```

---

### 6. Test 1: Unsigned Request → 401 Challenge

```bash
curl -i http://localhost:3001/ -H "Host: localhost"
```

Expected:
```http
HTTP/1.1 401 Unauthorized
aauth-requirement: requirement=auth-token, auth-server=""
www-authenticate: AAuth
content-type: application/json

{"error":"missing_signature"}
```

The `AAuth-Requirement` header tells the agent which auth server to talk to and that a signed request (or auth token) is required.

---

### 7. Test 2: Pseudonymous Signed Request → Passes Auth

The `cmd/sign-request` tool generates a fresh Ed25519 keypair, builds a valid RFC 9421 HTTP Message Signature, and prints the `curl` command:

```bash
./sign-request -method GET -authority localhost -path /
```

> **Important**: sign with `-authority localhost`, not `localhost:3001`. agentgateway passes the bare hostname to the ExtAuthZ service — what you sign must match what the service sees.

Sample output:
```bash
curl -si -X GET 'http://localhost/' \
  -H 'Content-Type: application/json' \
  -H 'signature-key: sig=hwk;kty="OKP";crv="Ed25519";x="<base64url-pubkey>"' \
  -H 'signature-input: sig=("@method" "@authority" "@path" "signature-key");created=...;alg="ed25519"' \
  -H 'signature: sig=:<base64-sig>:'
```

Send to agentgateway on port 3001 (override the URL but keep the `Host: localhost` default):

```bash
./sign-request -method GET -authority localhost -path / \
  | sed 's|http://localhost/|http://localhost:3001/|' \
  | bash
```

Or more explicitly:

```bash
# Capture headers
SIGNED=$(./sign-request -method GET -authority localhost -path /)
SK=$(echo "$SIGNED" | grep "signature-key:"  | sed "s/.*'signature-key: //;s/'.*//")
SI=$(echo "$SIGNED" | grep "signature-input:" | sed "s/.*'signature-input: //;s/'.*//")
SG=$(echo "$SIGNED" | grep "^  -H 'signature: " | sed "s/.*'signature: //;s/'.*//")

curl -i http://localhost:3001/ \
  -H "Host: localhost" \
  -H "signature-key: $SK" \
  -H "signature-input: $SI" \
  -H "signature: $SG"
```

Expected — auth passes, backend error (not a 401):
```http
HTTP/1.1 406 Not Acceptable
mcp: client must accept both application/json and text/event-stream
```

The `406` is the MCP backend rejecting the request due to missing `Accept` headers. The fact that it is **not** a `401` proves the auth gate was cleared.

---

### 8. Test 3: Inspect What the Service Extracted

Check the structured decision log in the AAuth service terminal:

```json
{"time":"...","resource_id":"mcp-api","level":"pseudonymous","result":"allowed","latency_ms":0}
```

Upstream headers added by the service (visible to the backend):
- `x-aauth-level: pseudonymous`
- `x-aauth-jkt: <RFC 7638 SHA-256 thumbprint of the signing key>`

---

### 9. Test 4: JWKS and Metadata Endpoints

```bash
# Resource metadata (tells agents where to get auth tokens and resource tokens)
curl -s http://localhost:8080/.well-known/aauth-resource.json | jq .
```

```json
{
  "issuer": "http://localhost:8080",
  "jwks_uri": "http://localhost:8080/.well-known/jwks.json",
  "authorization_endpoint": "",
  "resource_token_endpoint": "http://localhost:8080/resource/token",
  "signature_window": 60,
  "supported_scopes": null
}
```

```bash
# JWKS (public key used to verify resource-tokens the service mints)
curl -s http://localhost:8080/.well-known/jwks.json | jq .
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

### 10. Automated Integration Test

A Python-based integration test that drives all of the above in one shot:

```bash
# With both services running:
python3 - << 'EOF'
import subprocess, urllib.request, json

PASS, FAIL = 0, 0
def ok(m):   global PASS; PASS += 1; print(f"  PASS: {m}")
def fail(m): global FAIL; FAIL += 1; print(f"  FAIL: {m}")

# TEST 1: unsigned → 401
req = urllib.request.Request("http://localhost:3001/", method="GET")
try:
    urllib.request.urlopen(req)
    fail("expected 401")
except urllib.error.HTTPError as e:
    ok(f"401") if e.code == 401 else fail(f"got {e.code}")
    hdrs = dict(e.headers)
    ok("AAuth-Requirement") if 'aauth-requirement' in hdrs else fail("missing AAuth-Requirement")

# TEST 2: signed hwk → not 401
r = subprocess.run(["./sign-request","-method","GET","-authority","localhost","-path","/"],
                   capture_output=True, text=True)
headers = {}
for line in r.stdout.split('\n'):
    for k in ['signature-key','signature-input','signature']:
        if f"'{k}:" in line:
            headers[k] = line.split(f"'{k}: ",1)[1].rstrip("' \\")

req2 = urllib.request.Request("http://localhost:3001/", method="GET")
req2.add_header("Host","localhost")
for k,v in headers.items(): req2.add_header(k,v)
try:
    urllib.request.urlopen(req2)
    ok("allowed (200)")
except urllib.error.HTTPError as e:
    fail(f"got 401 — auth rejected signed request") if e.code==401 else ok(f"allowed ({e.code})")

# TEST 3: JWKS
jwks = json.loads(urllib.request.urlopen("http://localhost:8080/.well-known/jwks.json").read())
ok(f"JWKS has {len(jwks['keys'])} key(s) with x={bool(jwks['keys'][0].get('x'))}") if jwks.get('keys') else fail("no keys")

print(f"\nPassed: {PASS}  Failed: {FAIL}")
EOF
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

1. **Port stripping**: agentgateway passes the bare hostname (without port) as the `host` in CheckRequests. Include the bare hostname in the resource's `hosts` list and sign with `-authority <hostname>` (no port).

2. **Context extensions**: the `aauth_resource_id` extension maps a route directly to a resource config:
   ```yaml
   extAuthz:
     host: "localhost:7070"
     protocol:
       grpc:
         context:
           aauth_resource_id: "my-resource"
   ```
   Without this, the service falls back to Host-header based lookup.

3. **Strip signature headers**: set `strip_signature_headers: true` in the resource config to remove `Signature`, `Signature-Input`, and `Signature-Key` before the request reaches the backend.

---

## Upstream Headers

On a successful auth check the service adds these headers to the upstream request:

| Header | When present | Content |
|--------|-------------|---------|
| `x-aauth-level` | Always | `pseudonymous`, `identified`, or `authorized` |
| `x-aauth-jkt` | Always | RFC 7638 SHA-256 JWK thumbprint of the signing key |
| `x-aauth-agent-server` | `identified`/`authorized` | Issuer URL of the agent server |
| `x-aauth-delegate` | `identified`/`authorized` | `sub` claim from the agent/auth token |
| `x-aauth-scope` | `authorized` | Space-separated granted scopes |
| `x-aauth-txn` | `authorized`, if present | Transaction ID from the auth token |

---

## Observability

Prometheus metrics at `GET http://localhost:8080/metrics`:
- `aauth_check_total{resource,level,result}` — hit rates, identity levels, error classes
- `aauth_check_duration_seconds{resource,result}` — per-decision latency histogram
- `aauth_jwks_fetch_total{uri,result}` — JWKS fetch cache hit/miss rates

Structured JSON decision log on stdout for every check:
```json
{"time":"...","resource_id":"mcp-api","level":"pseudonymous","result":"allowed","latency_ms":0}
```

---

## Tools

| Tool | Purpose |
|------|---------|
| `go run ./cmd/generate-key` or `make generate-key` | Generate an Ed25519 keypair as PEM files |
| `go run ./cmd/sign-request` or `make build-sign-request` | Generate a signed `curl` command for testing |
| `go run ./cmd/debug-extauthz` | gRPC inspector that dumps every CheckRequest (listens on `:7071`) |
| `go run ./cmd/integration-test` | Direct gRPC integration test against a running service |
