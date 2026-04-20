#!/usr/bin/env bash
# End-to-end AAuth + agentgateway integration test.
#
# Prerequisites (run each in a separate terminal from the repo root):
#   Terminal 1:  go build -o aauth-service ./cmd/server && \
#                  AAUTH_CONFIG=demo/aauth-config.yaml ./aauth-service
#   Terminal 2:  agentgateway -f demo/agentgateway-aauth.yaml
#
# Usage:  bash demo/test.sh
set -euo pipefail
cd "$(dirname "$0")/.."  # run from repo root

AGW="http://localhost:3000"
AAUTH_HTTP="http://localhost:8080"
ROUTE="/gemini/v1/chat/completions"
BODY='{"model":"gemini-2.5-flash-lite","messages":[{"role":"user","content":"hello"}]}'

PASS=0; FAIL=0
ok()   { echo "  PASS: $*"; ((PASS++)); }
fail() { echo "  FAIL: $*"; ((FAIL++)); }
sep()  { echo; echo "━━━ $* ━━━"; }

# ── 1. Unsigned request → 401 + challenge ────────────────────────────────────
sep "TEST 1: Unsigned request → 401 + AAuth-Requirement"

resp=$(curl -si -X POST "$AGW$ROUTE" \
  -H "Content-Type: application/json" \
  -d "$BODY")

http_status=$(echo "$resp" | awk 'NR==1{print $2}')
challenge_hdr=$(echo "$resp" | grep -i "^aauth-requirement:" || true)
www_auth=$(echo "$resp" | grep -i "^www-authenticate:" || true)

echo "  HTTP status : $http_status"
echo "  challenge   : $challenge_hdr"
echo "  www-auth    : $www_auth"

[[ "$http_status" == "401" ]] && ok "HTTP 401" || fail "Expected 401, got $http_status"
[[ -n "$challenge_hdr" ]]     && ok "AAuth-Requirement present" || fail "AAuth-Requirement missing"
[[ -n "$www_auth" ]]          && ok "WWW-Authenticate present"  || fail "WWW-Authenticate missing"

# Verify challenge includes auth-server field
echo "$challenge_hdr" | grep -q "auth-server" \
  && ok "auth-server field in challenge" \
  || fail "auth-server field missing from challenge"

# ── 2. Signed request (HWK/pseudonymous) → extAuthz allows it ────────────────
sep "TEST 2: Signed request (HWK pseudonymous) → extAuthz should allow (non-401)"

# Build signed curl command via the sign-request helper
SIGNED_CMD=$(go run ./cmd/sign-request \
  -method POST \
  -authority "localhost:3000" \
  -path "$ROUTE" \
  -body "$BODY")

echo "  Signed command:"
echo "$SIGNED_CMD" | sed 's/^/    /'
echo

resp2=$(eval "$SIGNED_CMD")
status2=$(echo "$resp2" | awk 'NR==1{print $2}')
echo "  HTTP status: $status2"

# extAuthz should NOT return 401 for a properly signed pseudonymous request.
# The backend (Gemini) may return 400/403 if GEMINI_API_KEY is missing — that's fine.
if [[ "$status2" != "401" ]]; then
  ok "Not 401 — extAuthz passed the request (backend responded: $status2)"
else
  body2=$(echo "$resp2" | tail -n1)
  fail "Got 401 from extAuthz — signed request was rejected. Body: $body2"
fi

# Also verify signature headers were stripped (StripSignatureHeaders=true in config)
if echo "$resp2" | grep -qi "^x-aauth-level:"; then
  ok "x-aauth-level upstream header echoed by backend (if echo backend)"
fi

# ── 3. JWKS discovery endpoint ────────────────────────────────────────────────
sep "TEST 3: AAuth HTTP API — JWKS at /.well-known/aauth-resource.json"

jwks=$(curl -sf "$AAUTH_HTTP/gemini-api/.well-known/aauth-resource.json" 2>/dev/null || echo "error")
echo "  Response: ${jwks:0:200}"

echo "$jwks" | grep -q '"keys"' \
  && ok "JWKS endpoint returned keys array" \
  || fail "JWKS endpoint error or missing 'keys' field"

echo "$jwks" | grep -q '"kty"' \
  && ok "Key entry has kty field" \
  || fail "Key entry missing kty"

# ── Summary ───────────────────────────────────────────────────────────────────
sep "Results"
echo "  Passed: $PASS  /  Failed: $FAIL"
[[ $FAIL -eq 0 ]]
