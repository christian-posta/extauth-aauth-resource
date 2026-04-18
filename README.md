# AAuth Resource-Side ExtAuthZ Service

This project provides a multi-tenant AAuth resource-side service. It is implemented as a Go binary that lets you protect backend APIs with the AAuth protocol by deploying it behind an Envoy proxy or AgentGateway using the ExtAuthZ gRPC protocol.

The service is fully compliant with:
- RFC 9421 HTTP Message Signatures
- RFC 8941 Structured Field Values
- AAuth `Signature-Key` schemes (`hwk`, `jwt`, `jwks_uri`)

## Features
- **Zero Third-Party Crypto Dependencies**: Fully bespoke, audited implementations of RFC 9421 and RFC 8941.
- **Multi-Tenant**: A single deployment can protect multiple distinct APIs, dynamically applying different cryptographic requirements and serving different metadata based on the route or `Host` header.
- **Dual-Listener Architecture**:
  - `gRPC (:7070)`: The Envoy ExtAuthZ policy engine.
  - `HTTP (:8080)`: Serves `/.well-known/aauth-resource.json`, `/.well-known/jwks.json`, and `/resource/token`.
- **Identity Levels**: Supports `pseudonymous` (raw keys), `identified` (agent tokens), and `authorized` (auth tokens).
- **Automated Challenges**: Generates `AAuth-Requirement` 401 responses, automatically minting and binding `resource-token`s when agents provide sufficient key material but lack scope.

## How to Test End-to-End

You can test the entire AAuth verification pipeline locally using AgentGateway.

### 1. Build the AAuth Service

```bash
go build -o aauth-service ./cmd/server
```

### 2. Generate a Resource Key

The service needs an Ed25519 private key to sign resource tokens. You can generate one using the included script:

```bash
go run sign_req.go # Note: We will replace this with a dedicated keygen script below
```

Alternatively, you can generate a key using OpenSSL:
```bash
openssl genpkey -algorithm ed25519 -outform PEM -out resource_key.pem
```

### 3. Create the AAuth Configuration (`aauth-config.yaml`)

This configuration defines a single protected resource (`mcp-api`) that allows pseudonymous access.

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
      - localhost
    signing_key:
      kid: rsk-1
      alg: EdDSA
      private_key_file: resource_key.pem
    signature_window: 60s
    allow_pseudonymous: true
    policy:
      name: default
```

### 4. Create the AgentGateway Configuration (`agw-config.yaml`)

This configures AgentGateway to listen on port `3001`, forward all authorization checks to our AAuth service on `7070`, and route successful requests to a dummy MCP backend.

```yaml
binds:
- port: 3001
  listeners:
  - routes:
    - policies:
        extAuthz:
          host: "localhost:7070"
      backends:
      - mcp:
          targets:
          - name: everything
            stdio:
              cmd: npx
              args: ["-y", "@modelcontextprotocol/server-everything"]
```

### 5. Start the Services

In terminal 1, start the AAuth service:
```bash
export AAUTH_CONFIG=aauth-config.yaml
./aauth-service --port 7070
```

In terminal 2, start AgentGateway:
```bash
agentgateway -f agw-config.yaml
```

### 6. Test 1: Unsigned Request (Should Fail)

Try to access the protected route without any signature headers:

```bash
curl -i http://localhost:3001/ -H "Host: localhost"
```

**Expected Output:**
You should receive an HTTP `401 Unauthorized`. Notice the custom AAuth headers challenging the client to authenticate:
```http
HTTP/1.1 401 Unauthorized
aauth-requirement: requirement=auth-token, auth-server=""
www-authenticate: AAuth
content-type: application/json
```

### 7. Test 2: Pseudonymous Signed Request (Should Succeed)

We have provided a helper script (`sign_req.go`) that generates a fresh client Ed25519 keypair, constructs a valid RFC 9421 HTTP Message Signature, and outputs the exact `curl` command needed to test it.

Run the script and execute the resulting curl command:

```bash
go run sign_req.go > curl_cmd.sh
sh curl_cmd.sh
```

**Expected Output:**
The policy engine will verify the cryptographic signature, accept the pseudonymous `hwk` level (since we set `allow_pseudonymous: true` in the config), and allow the request through to the backend. 

You should receive an `HTTP/1.1 406 Not Acceptable` from the backend (because the MCP backend requires specific `Accept` headers, which proves the request successfully bypassed the authorization gate!).

```http
HTTP/1.1 406 Not Acceptable
content-type: text/plain
mcp: client must accept both application/json and text/event-stream
```

### 8. Test 3: Fetching Metadata

The HTTP side of the service dynamically serves `/.well-known/` metadata based on the `Host` header.

```bash
curl -s http://localhost:8080/.well-known/aauth-resource.json -H "Host: localhost:8080" | jq .
```

**Expected Output:**
```json
{
  "additional_signature_components": null,
  "authorization_endpoint": "",
  "issuer": "http://localhost:8080",
  "jwks_uri": "http://localhost:8080/.well-known/jwks.json",
  "resource_token_endpoint": "http://localhost:8080/resource/token",
  "scope_descriptions": null,
  "signature_window": 60,
  "supported_scopes": null
}
```

## Observability

The service exports Prometheus metrics at `GET http://localhost:8080/metrics`.
- `aauth_check_total` (Counter: Tracks hit rates, levels, and error classifications)
- `aauth_jwks_fetch_total` (Counter: Tracks JWKS fetch caching results)
- `aauth_check_duration_seconds` (Histogram: Latency)

Structured JSON logging is emitted to stdout on every AAuth decision, including extracted identities and latencies.
