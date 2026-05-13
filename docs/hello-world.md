# Hello World — End-to-End AAuth Walkthrough

A working three-process demo of identified-level AAuth: the resource service
gates access, agentgateway proxies traffic, and a Go agent client signs the
request and publishes the well-known metadata the resource service needs to
verify it.

What you'll see:

- An unsigned request gets a 401 + `AAuth-Requirement` challenge.
- A signed request from the agent client is admitted, with `x-aauth-level: identified` flowing to the upstream backend.
- Two `identified` schemes covered: `jwks_uri` (discovery-based) and `aa-agent+jwt` (JWT-based, with the request key bound via `cnf.jwk`).

```
                                   verify (JWKS fetch)
                       ┌─────────────────────────────────────┐
                       ▼                                     │
   ┌────────────────────┐                              ┌─────┴────────┐
   │ aauth-service      │                              │ agent-client │
   │  gRPC :7070        │                              │   :9099      │
   │  HTTP :8090        │                              │  /.well-known│
   └────────────────────┘                              │     /echo    │
            ▲                                          └──────────────┘
            │ ext_authz                                       ▲
            │                                                 │ proxied
   ┌────────┴───────────┐                                     │ request
   │ agentgateway :3001 │─────────────────────────────────────┘
   └────────────────────┘
            ▲
            │ signed HTTP request
   ┌────────┴───────────┐
   │ agent-client (CLI) │   (same binary; sends the request and exits)
   └────────────────────┘
```

The `agent-client` binary plays both roles: a long-lived "agent server" that
hosts `/.well-known/aauth-agent.json` + `/.well-known/jwks.json` (and `/echo`,
which doubles as the upstream backend so the demo has zero external
dependencies), and a short-lived CLI invocation that signs and sends the
request. Both invocations share the same on-disk keystore, so the JWKS the
resource fetches stays consistent.

## Prerequisites

- Go 1.24+
- [`agentgateway`](https://github.com/agentgateway/agentgateway) on your `$PATH`
- `jq` (optional, for inspecting JSON responses)
- Free ports: `3001` (agentgateway), `7070` + `8090` (aauth-service), `9099` (agent-client)

## 1. Build

```bash
make build build-agent-client
```

This produces `./aauth-service` and `./agent-client` in the repo root.

## 2. Generate the resource signing key

```bash
cd demo/hello-world && go run ../../cmd/generate-key && cd -
```

Creates `demo/hello-world/resource_key.pem` (and `resource_pub.pem`). Skip if
the files already exist.

## 3. Start the AAuth resource service

In terminal A:

```bash
AAUTH_CONFIG=demo/hello-world/aauth-config.yaml ./aauth-service
```

You should see:

```
Configured resource id="hello-world-api" issuer="http://localhost:3001" hosts=[localhost:3001]
Starting HTTP API on :8090
Policy Engine starting on :7070
```

The config trusts a single agent server at `http://127.0.0.1:9099` and accepts
both `jwks_uri` and `aa-agent+jwt` schemes at identity level — see
[`demo/hello-world/aauth-config.yaml`](../demo/hello-world/aauth-config.yaml).

## 4. Start agentgateway

In terminal B:

```bash
agentgateway -f demo/hello-world/agw-config.yaml
```

Listens on `:3001`, delegates auth to `localhost:7070`, and proxies the
incoming request to `127.0.0.1:9099` — which is the same `agent-client`
process we'll start next. Resource discovery (`/.well-known/*`, `/resource/*`)
is forwarded to the AAuth HTTP API on `:8090` without ExtAuthZ.

You can confirm the resource metadata through the gateway:

```bash
curl -s http://localhost:3001/.well-known/aauth-resource.json | jq .
```

## 5. Start the agent server (long-lived half of agent-client)

In terminal C:

```bash
./agent-client -serve
```

This generates fresh agent keys (saved to `agent-client-keys.json` in the
working directory), prints the kids, and serves:

- `http://127.0.0.1:9099/.well-known/aauth-agent.json` — agent server metadata
- `http://127.0.0.1:9099/.well-known/jwks.json` — both keys (the request signing key and the agent-server signing key)
- `http://127.0.0.1:9099/echo` — the upstream backend that mirrors the request

Leave it running. Inspect what it publishes:

```bash
curl -s http://127.0.0.1:9099/.well-known/aauth-agent.json | jq .
curl -s http://127.0.0.1:9099/.well-known/jwks.json        | jq .
```

## 6. The negative case — unsigned request

In terminal D:

```bash
curl -i http://localhost:3001/echo -H "Host: localhost"
```

Expected:

```
HTTP/1.1 401 Unauthorized
aauth-requirement: requirement=auth-token
www-authenticate: AAuth
signature-error: error=invalid_signature
accept-signature: sig2=("@method" "@authority" "@path");sigkey=uri

{"error":"missing_signature"}
```

The resource service refuses the request and tells the caller what would have
satisfied it.

## 7. Mode A — `jwks_uri` scheme

```bash
./agent-client -mode jwks_uri \
  -target http://localhost:3001/echo \
  -authority localhost
```

The client signs with the persisted request key and sets:

```
signature-key: sig=jwks_uri;id="http://127.0.0.1:9099";dwk="aauth-agent.json";kid="req-..."
```

The resource service fetches `http://127.0.0.1:9099/.well-known/aauth-agent.json`,
follows `jwks_uri`, looks up the kid, and verifies the request signature.

Expected response (truncated):

```
HTTP/1.1 200 OK

{
  "headers": {
    "X-Aauth-Agent-Server": "http://127.0.0.1:9099",
    "X-Aauth-Jkt": "...",
    "X-Aauth-Level": "identified"
  },
  "host": "localhost",
  "method": "GET",
  "path": "/echo"
}
```

The upstream backend (just our `/echo` handler) sees the `x-aauth-*` headers
the resource service adds — these are what an MCP server, an API, or any
real upstream would use to enforce per-agent authorization.

## 8. Mode B — `aa-agent+jwt` scheme

```bash
./agent-client -mode agent-jwt \
  -target http://localhost:3001/echo \
  -authority localhost
```

This time the client mints an `aa-agent+jwt` signed by the long-lived
agent-server key. The JWT carries `cnf.jwk` = the public half of the request
signing key, so the resource service can verify the request signature against
the key the JWT vouches for.

```
signature-key: sig=jwt;jwt="eyJhbGciOiJFZERTQSI...<aa-agent+jwt>..."
```

Verification flow:

1. Parse the JWT header → `typ=aa-agent+jwt`, `kid=agentserver-...`
2. Discover the issuer — `http://127.0.0.1:9099/.well-known/aauth-agent.json`.
3. Fetch the JWKS, look up the agent-server kid, verify the JWT signature.
4. Extract `cnf.jwk` and use it to verify the HTTP message signature on the
   request itself.

Same `200 OK` outcome, with `x-aauth-level: identified` and
`x-aauth-delegate` set to the `sub` claim from the JWT (the agent identifier).

## 9. What the decision log shows

Tail terminal A:

```
{"resource_id":"hello-world-api","level":"identified","agent_server":"http://127.0.0.1:9099","delegate":"aauth:demo@127.0.0.1","result":"allowed","latency_ms":1}
```

The same line is emitted on every check. `level=identified` is the entire
point of this walkthrough: the request didn't just come with a bare key
(pseudonymous), it came with provable claims about which agent server vouches
for it.

## 10. Cleanup

`Ctrl-C` each of terminals A, B, and C. The keystore at
`agent-client-keys.json` can be deleted to rotate keys; the next
`./agent-client` invocation will regenerate it.

## Variations

- **Different agent identity** — pass `-agent-id "aauth:bob@127.0.0.1"` to the
  CLI invocation. The `sub` claim flows through to `x-aauth-delegate`.
- **Send a POST body** — `./agent-client -mode jwks_uri -method POST -body '{"hello":"world"}'`.
- **Run agentgateway against a different backend** — edit
  [`demo/hello-world/agw-config.yaml`](../demo/hello-world/agw-config.yaml) to
  point `backends:` at any HTTP service. The agent-client's `-target` URL
  controls what the request asks for.
- **Mode 3 (auth-token / authorized)** — see [`docs/mode3.md`](mode3.md). That
  flow adds an Access Server that issues `aa-auth+jwt` after exchanging a
  resource-token; the agent's identity is one ingredient of the larger flow
  this hello-world covers.

## Why the resource config is set up the way it is

A few flags in [`demo/hello-world/aauth-config.yaml`](../demo/hello-world/aauth-config.yaml)
are tuned for the localhost demo and **should not be carried into production**:

- `allow_insecure_jwt_issuer: true` — required so `http://127.0.0.1:9099` is
  accepted as an `aa-agent+jwt` issuer. Production should keep this `false`
  so only `https://` issuers are accepted.
- `jwks_cache.success_ttl: 5s` — short cache TTL so the demo iterates without
  60-second waits. Production should use the default 5m or longer.
- `agent_servers:` lists the demo agent client by URL. Production lists real
  trusted agent server issuers (HTTPS).
