# Mode 2 — Resource-Managed OAuth Bridge

This document explains the **AAuth Mode 2 (resource-managed / two-party)** flow implemented
in this service, and walks through two ways to test it:

1. **Integration test with embedded stub OAuth** — fully automated, no browser, no GitHub account.
2. **Manual test with real GitHub OAuth** — exercises a live OAuth flow in your browser.

---

## How it works

```
Agent                   AgentGateway        aauth-service              GitHub OAuth
  │                         │                    │                          │
  │──── signed GET ─────────►─── Check gRPC ─────►                          │
  │                         │                    │ 202 + AAuth-Requirement  │
  │◄────────────────────────◄────────────────────│  (interaction; code=...) │
  │                         │                    │                          │
  │  (user visits url)      │                    │                          │
Browser──── GET /interaction?code=XX ────────────►                          │
  │                         │                    │──── 302 → /login/oauth ─►│
  │                         │                    │                          │ (user approves)
  │                         │                    │◄─── GET /oauth/callback ─│
  │                         │                    │  (exchange code→token)   │
  │                         │                    │  mark pending complete   │
  │                         │                    │                          │
  │──── signed GET /pending/{id} ───────────────►─── Check gRPC ────────────►
  │                         │                    │ 200 + AAuth-Access: ...  │
  │◄────────────────────────◄────────────────────│                          │
  │                         │                    │                          │
  │──── signed GET /api/X ──────────────────────►─── Check gRPC ────────────►
  │     Authorization: AAuth <opaque>            │ (unwrap token, verify)   │
  │                         │                    │ OK + Authorization: Bearer│
  │                         │──── upstream ──────►                          │
```

### Key points

- The agent calls the resource as normal (signed request). On the first call, the service
  issues a `202 Accepted` with `AAuth-Requirement: requirement=interaction; url=...; code=...`
  and `Location: /pending/{id}`.
- A **one-time interaction code** identifies the pending session. The agent must direct the
  user's browser to `{url}?code={code}`.
- `/interaction?code=...` is served by this service's HTTP listener, which redirects the
  browser through the configured upstream OAuth provider.
- The OAuth `redirect_uri` lands back at `/oauth/{resource-id}/callback` on this service.
  It exchanges the auth code for tokens, wraps them in an AES-256-GCM blob, and marks the
  pending entry complete.
- The agent polls `/pending/{id}` (still through agentgateway + ExtAuthZ) until the response
  is `200 OK` with `AAuth-Access: <opaque>`.
- Subsequent API calls include `Authorization: AAuth <opaque>` covered by the HTTP signature.
  This service unwraps the blob, verifies the agent-key binding, and injects
  `Authorization: Bearer <github-access-token>` for the upstream.

---

## Option A — Automated integration test (stub OAuth)

This is the fastest way to verify the full end-to-end flow. The integration test binary
embeds a minimal OAuth stub server that auto-approves any code, so no browser or real
OAuth provider is needed.

### 1. Build

```bash
make build
go build -o integration-test-mode2 ./cmd/integration-test-mode2
```

### 2. Generate a signing key (if you haven't already)

```bash
make generate-key   # creates demo/resource_key.pem + demo/resource_pub.pem
```

### 3. Terminal 1 — start aauth-service (standalone, no agentgateway needed)

The stub integration test connects directly to the aauth-service gRPC and HTTP listeners
(no agentgateway in the loop), so the resource is configured with issuer
`http://localhost:8080` (the HTTP listener):

```bash
AAUTH_CONFIG=demo/aauth-config-mode2.yaml ./aauth-service
```

You should see:

```
Configured resource id="github-api" issuer="http://localhost:8080" hosts=[localhost:8080]
WARNING: resource "github-api" has no opaque_token_key configured — using ephemeral key
Mode 2 (resource-managed OAuth bridge) enabled; interaction TTL=15m0s
Policy Engine starting on :7070
Starting HTTP API on :8080
```

### 4. Terminal 2 — run the integration test

```bash
./integration-test-mode2 \
  --grpc 127.0.0.1:7070 \
  --resource-issuer http://localhost:8080 \
  --resource-id github-api \
  --authority localhost:8080 \
  --path /api/test \
  --stub-oauth-port 19100
```

Expected output:

```
[stub] OAuth server on :19100; will issue token: stub-access-token-xxxxxxxx
Agent key generated (hwk scheme)
Connected to 127.0.0.1:7070

─── Step 1: initial request (expect 202 + AAuth-Requirement) ───
  interaction code: ABCD1234
  polling URL: http://localhost:8080/pending/deadbeef...

─── Step 2: browser visits interaction URL (auto-follows OAuth redirects) ───
  GET http://localhost:8080/interaction?code=ABCD1234
  → redirect http://localhost:19100/oauth/authorize?...
  → redirect http://localhost:8080/oauth/github-api/callback?code=stub-code-...&state=...
  browser flow complete (status 200)

─── Step 3: agent polls /pending/{id} ───
  poll 1: status=OK body={"status":"complete"}
  AAuth-Access: <opaque blob>

─── Step 4: API call with AAuth-Access token ───
  upstream header: Authorization: Bearer stub-access-token-xxxxxxxx

✓ PASS: injected Authorization: Bearer stub-access-token-xxxxxxxx

─── Step 5: negative test — different agent key reusing the token ───
  ✓ different agent correctly DENIED (status=Unauthorized body={"error":"invalid_token"})

✓ Mode 2 integration test PASSED (positive + negative)
```

---

## Option B — End-to-end with real GitHub OAuth

This uses the **same `integration-test-mode2` binary** as Option A, but with the
`--real-oauth` flag. The binary skips its built-in stub OAuth server, prints the
interaction URL, and pauses for you to complete the OAuth flow in your real browser
against GitHub. Once you press Enter, it polls and verifies that a real Bearer token
gets injected.

### 1. Register a GitHub OAuth App

1. Go to <https://github.com/settings/developers> → **New OAuth App**.
2. Fill in:
   - **Application name**: AAuth Mode 2 Demo (or anything)
   - **Homepage URL**: `http://localhost:8080`
   - **Authorization callback URL**: `http://localhost:8080/oauth/github-api/callback`
3. Click **Register application**.
4. Copy the **Client ID**.
5. Click **Generate a new client secret** and copy the secret.

### 2. Generate keys

```bash
# Ed25519 signing key for the resource (skip if already done from Option A)
make generate-key   # creates demo/resource_key.pem + demo/resource_pub.pem

# AES-256 key for wrapping OAuth tokens in AAuth-Access blobs
openssl rand -base64 32
# → copy this value; you'll paste it into the config below
```

### 3. Fill in `demo/aauth-config-mode2-github.yaml`

Open the file and replace the three placeholders. Example after editing:

```yaml
opaque_token_key:
  key_b64: "X5bGvZ3kqJ9qK8wPq+a9Q7gKx0/4F+JzD3VqHm2eU8Q="   # openssl rand output

oauth_bridge:
  client_id:     "Iv1.0123456789abcdef"
  client_secret: "0123456789abcdef0123456789abcdef01234567"
```

Leave the URLs (`authorize_url`, `token_url`, `redirect_uri_base`, `issuer`) as-is —
they are already correct for a standalone localhost setup.

### 4. Terminal 1 — start aauth-service

```bash
AAUTH_CONFIG=demo/aauth-config-mode2-github.yaml ./aauth-service
```

You should see:

```
Configured resource id="github-api" issuer="http://localhost:8080" hosts=[localhost:8080]
Mode 2 (resource-managed OAuth bridge) enabled; interaction TTL=15m0s
Policy Engine starting on :7070
Starting HTTP API on :8080
```

(No "WARNING: ephemeral key" message this time — your `key_b64` is being used.)

### 5. Terminal 2 — run the driver

```bash
./integration-test-mode2 \
  --grpc 127.0.0.1:7070 \
  --resource-issuer http://localhost:8080 \
  --resource-id github-api \
  --authority localhost:8080 \
  --path /api/test \
  --real-oauth
```

The test will pause at Step 2 and print something like:

```
─── Step 2: open this URL in your browser, complete the OAuth flow, then press Enter ───

  http://localhost:8080/interaction?code=ABCD1234

Press Enter once you see the "Authorization complete" page in the browser…
```

### 6. Complete the OAuth flow in your browser

Open the printed URL in your browser. You will be:

1. Redirected to `github.com/login/oauth/authorize` (log in if you aren't already).
2. Asked to authorize the OAuth App's requested scopes (`read:user`, `repo` by default).
3. Redirected back to `http://localhost:8080/oauth/github-api/callback?...`
4. Shown an "Authorization complete" page.

Once you see the "Authorization complete" page, return to Terminal 2 and **press Enter**.

### 7. Watch the test finish

The test should print:

```
─── Step 3: agent polls /pending/{id} ───
  poll 1: status=OK body={"status":"complete"}
  AAuth-Access: <opaque blob>...

─── Step 4: API call with AAuth-Access token ───
  upstream header: Authorization: Bearer gho_<actual-github-token>
  upstream header: x-aauth-level: pseudonymous
  upstream header: x-aauth-jkt: <agent thumbprint>

✓ PASS: injected Authorization: Bearer gho_<actual-github-token>... (real OAuth token, NN chars)
  Try it against the provider:
    curl -H 'Authorization: Bearer gho_<actual-github-token>' https://api.github.com/user

─── Step 5: negative test — different agent key reusing the token ───
  ✓ different agent correctly DENIED (status=Unauthorized body={"error":"invalid_token"})

✓ Mode 2 integration test PASSED (positive + negative)
```

### 8. Prove the token works against the real GitHub API

Copy the printed `curl` command. Run it:

```bash
curl -H 'Authorization: Bearer gho_<actual-github-token>' https://api.github.com/user
```

You should see your GitHub user JSON. That confirms the full flow:

- Your agent never touched GitHub directly.
- The aauth-service brokered the OAuth flow, wrapped the GitHub access token in an
  encrypted opaque blob, and gave that blob to the agent.
- On the API call, ExtAuthZ unwrapped the blob, verified it was bound to the same agent
  key that started the flow, and gave the upstream proxy a `Authorization: Bearer <real
  GitHub token>` header.

In a production setup the upstream would be GitHub itself (routed via agentgateway);
here we use ExtAuthZ to inject the Bearer and let you verify the token out-of-band.

---

## Troubleshooting

### GitHub error: `redirect_uri_mismatch`

The GitHub OAuth App's "Authorization callback URL" must match `redirect_uri_base` +
`/oauth/{resource-id}/callback` **exactly** — same scheme, host, port, and path.
For the demo, that is `http://localhost:8080/oauth/github-api/callback`.
Update either the GitHub app settings or the config to match.

### Test pauses forever at Step 2

You opened the URL but never saw "Authorization complete." Common causes:
- The OAuth App settings on GitHub still point at the old callback URL — update them and
  retry from Step 5.
- The `client_secret` is wrong — the code exchange will fail and the page will show an
  "Authorization error." Tail the aauth-service log: `oauth_callback: code exchange failed`.
- The GitHub OAuth App is set to "Request user authorization (OAuth) during installation"
  on a GitHub App rather than an OAuth App — those are different products. Use a classic
  OAuth App (Settings → Developer settings → OAuth Apps).

### `oauth_callback: missing PKCE cookie`

GitHub does not support PKCE. Set `use_pkce: false` in `oauth_bridge` and restart the service.

### `oauth_callback: code exchange failed … Accept header`

The GitHub token endpoint requires `Accept: application/json`. This is set automatically
by the `oauthbridge` package. If you see this with a non-GitHub provider, check that your
`token_url` points to the correct endpoint.

### `handleAAuthAccess: agent JKT mismatch`

The AAuth-Access token is bound to the signing key that sent the original challenge
request. If you generate a new agent key and try to reuse an old token, this error is
expected. Request a new token by sending an unsigned (or differently-signed) request to
re-trigger the interaction flow.

### Token wrap/unwrap fails after restart

The AES-256 key is generated **ephemerally at startup** if `opaque_token_key` is not
configured. Any outstanding tokens become invalid after a restart. Configure an explicit
`key_b64` in production to survive restarts.

### The browser is redirected to `localhost` but I'm on a remote machine

The `redirect_uri_base` in the config must be reachable by the user's browser, not just
the server. For remote testing, replace `http://localhost:8080` with a publicly accessible
URL (e.g., via `ngrok http 8080`), update the GitHub OAuth App callback URL to match, and
update both `redirect_uri_base` and the `issuer` in the config.

---

## Configuration reference

### `access.require: interaction`

Enables Mode 2 for this resource. Every request that does not carry a valid
`Authorization: AAuth <opaque>` header will be challenged.

### `oauth_bridge`

| Field | Description |
|-------|-------------|
| `authorize_url` | OAuth authorization endpoint (e.g. `https://github.com/login/oauth/authorize`) |
| `token_url` | Token endpoint for code exchange |
| `client_id` | OAuth client ID |
| `client_secret` | OAuth client secret (keep out of version control) |
| `scopes` | Space-joined list of requested scopes |
| `use_pkce` | Enable PKCE S256 challenge (RFC 7636). GitHub standard OAuth Apps do not support PKCE. |
| `redirect_uri_base` | Base URL for the callback (e.g. `http://localhost:8080` for standalone, or your agentgateway public URL). Callback = `{base}/oauth/{resource-id}/callback`. Must match your provider's registered redirect URI. |
| `extra_auth_params` | Optional extra query parameters appended to the authorization URL |

### `opaque_token_key`

| Field | Description |
|-------|-------------|
| `key_b64` | Inline base64-encoded 32-byte AES-256 key |
| `key_file` | Path to a file containing a base64-encoded 32-byte key |

If neither is set, an ephemeral key is generated at startup (tokens become invalid on restart).

### `interaction_ttl`

Maximum time for the interaction flow to complete (default `15m`). If the user does not
complete the OAuth flow within this window, the pending entry expires and the agent must
re-trigger the challenge.

### `success_redirect`

Optional URL the browser is redirected to after the OAuth callback completes. If empty,
a static "you may close this window" page is shown.

---

## Option C — With agentgateway in front (production-shaped)

In production agentgateway sits in front of aauth-service as the public-facing listener
(port 3001 in the demo). All agent and browser traffic flows through it. Two route
classes:

| Path prefix | Route | Why |
|---|---|---|
| `/.well-known/*`, `/resource/*`, `/interaction`, `/oauth/*` | direct to aauth HTTP (no ExtAuthZ) | metadata + browser interaction endpoints |
| `/pending/*` and everything else | through ExtAuthZ to the backend | agent polls + protected API are signature-verified |

```
┌──────┐    ┌──────────────┐  ExtAuthZ gRPC   ┌──────────────┐  Bearer    ┌──────────┐
│agent │───▶│ agentgateway │─────────────────▶│ aauth-service│            │  upstream│
│      │    │   :3001      │                  │  :7070 gRPC  │            │ (httpbin │
│      │    │              │                  │  :8080 HTTP  │            │ /github) │
└──────┘    └──────────────┘ ◀──── allow ─────└──────────────┘            └──────────┘
              │                                       ▲
              │ /interaction, /oauth/* (no ExtAuthZ)  │
              └───────────────────────────────────────┘
```

### 1. Build (skip if you already did)

```bash
make build
make build-integration-test-mode2
make generate-key
```

### 2. Terminal 1 — start aauth-service (agentgateway-fronted config)

```bash
AAUTH_CONFIG=demo/aauth-config-mode2-agw.yaml ./aauth-service
```

This config differs from `aauth-config-mode2.yaml` in three places: `issuer`,
`hosts`, and `redirect_uri_base` all point at the agentgateway URL
(`http://localhost:3001`) instead of the aauth-service HTTP port.

### 3. Terminal 2 — start agentgateway

```bash
agentgateway -f demo/agw-config-mode2.yaml
```

You should see `started bind bind="bind/3001"` in the log.

### 4. Terminal 3 — run the integration test through agw

```bash
./integration-test-mode2 \
  --grpc 127.0.0.1:7070 \
  --resource-issuer http://localhost:3001 \
  --resource-id github-api \
  --authority localhost:3001 \
  --path /api/test \
  --stub-oauth-port 19100 \
  --via-agw http://localhost:3001
```

The `--via-agw` flag adds **Step 4b**: after the gRPC Check proves Bearer injection,
the test also makes a **real HTTP request to agentgateway** with the AAuth-Access
header (signed). agentgateway routes through ExtAuthZ (which unwraps and authorizes),
then forwards to the upstream backend (httpbin.org in the demo). The test asserts
that httpbin's echo response contains the injected Bearer header.

Expected new section in the output:

```
─── Step 4b: same call routed through agentgateway → httpbin ───
  POST http://localhost:3001/headers (signed; Authorization: AAuth …)
  response status: 200
  ✓ httpbin saw the Bearer header (agentgateway → ExtAuthZ → upstream path verified)
  httpbin echo: "Authorization": "Bearer stub-access-token-...",
    "Host": "httpbin.org",
    "User-Agent": "Go-http-cl…
```

That single line — `httpbin echo: "Authorization": "Bearer ..."` — is the proof:
agentgateway accepted the agent's signed AAuth request, called ExtAuthZ over gRPC,
ExtAuthZ unwrapped the opaque token, ExtAuthZ told agentgateway to forward with
`Authorization: Bearer <oauth-token>`, agentgateway did, and the upstream received it.

### 5. (Optional) Try a curl against the agentgateway to see a challenge

An agent without identity will be challenged at the agentgateway boundary:

```bash
curl -si http://localhost:3001/headers
```

You'll see something like:

```
HTTP/1.1 401 Unauthorized
www-authenticate: AAuth
aauth-requirement: requirement=auth-token
signature-error: error=invalid_signature

{"error":"missing_signature"}
```

The actual Mode-2 `202 Accepted` + `AAuth-Requirement: requirement=interaction` shows
up once the request carries a valid AAuth identity. Triggering that from `curl` alone
requires constructing an HTTP Message Signature, which is what the integration test
does for you.

---

## Option D — Real GitHub with agentgateway

Combine Option B (real GitHub OAuth) with Option C (agentgateway routing). The agent's
final API calls now actually hit `api.github.com` via agentgateway.

### 1. Update the GitHub OAuth App

Change the **Authorization callback URL** to the agentgateway-fronted one:

```
http://localhost:3001/oauth/github-api/callback
```

### 2. Make an agentgateway-fronted GitHub config

Copy `demo/aauth-config-mode2-github.yaml` to `demo/aauth-config-mode2-github-agw.yaml`
and change three fields:

```yaml
resources:
  - id: github-api
    issuer: "http://localhost:3001"      # was localhost:8080
    hosts:
      - "localhost:3001"                  # was localhost:8080

    oauth_bridge:
      redirect_uri_base: "http://localhost:3001"   # was localhost:8080
```

### 3. Uncomment the `github-api-proxy` route in `demo/agw-config-mode2.yaml`

Find the `# # ── Variant: forward to real GitHub API ──` block at the bottom of
`demo/agw-config-mode2.yaml` and uncomment it. This adds a `/api/*` route that proxies
to `api.github.com:443` with the Host header rewritten so GitHub recognizes the
request.

### 4. Start the stack

```bash
# Terminal 1
AAUTH_CONFIG=demo/aauth-config-mode2-github-agw.yaml ./aauth-service

# Terminal 2
agentgateway -f demo/agw-config-mode2.yaml
```

### 5. Drive the flow with real GitHub, asserting against api.github.com

```bash
# Terminal 3
./integration-test-mode2 \
  --grpc 127.0.0.1:7070 \
  --resource-issuer http://localhost:3001 \
  --resource-id github-api \
  --authority localhost:3001 \
  --path /api/user \
  --real-oauth \
  --via-agw http://localhost:3001
```

The `--path /api/user` is important: with the `github-api-proxy` route in place,
agentgateway rewrites this to `https://api.github.com/user` after ExtAuthZ allows.
Step 4b's httpbin assertion won't apply directly here — instead the response body will
be your GitHub user JSON. The test still verifies that the response is 200 and that
the response body looks like a successful authenticated GitHub API response. If the
test passes, you've just made a real authenticated GitHub API call through the
full agentgateway + AAuth Mode 2 stack.

### 6. Quick out-of-band sanity check

The integration test prints the raw GitHub access token. Copy it and verify
out-of-band:

```bash
curl -H 'Authorization: Bearer <token-from-test>' https://api.github.com/user
```

You should see your GitHub profile JSON. That's the same token agentgateway is
injecting on every authorized agent call.
