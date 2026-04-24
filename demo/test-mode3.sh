#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

PASS=0
FAIL=0
ok()   { echo "  PASS: $*"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $*"; FAIL=$((FAIL + 1)); }
sep()  { echo; echo "━━━ $* ━━━"; }

GOCACHE_DIR="$(pwd)/.gocache"
GRPC_ADDR="127.0.0.1:17070"
HTTP_BASE="http://127.0.0.1:18090"
PS_BASE="http://127.0.0.1:9191"

AAUTH_PID=""
PS_PID=""
cleanup() {
  [[ -n "$AAUTH_PID" ]] && kill "$AAUTH_PID" >/dev/null 2>&1 || true
  [[ -n "$PS_PID" ]] && kill "$PS_PID" >/dev/null 2>&1 || true
}
trap cleanup EXIT

sep "BUILD BINARIES"
GOCACHE="$GOCACHE_DIR" go build -o aauth-service ./cmd/server
GOCACHE="$GOCACHE_DIR" go build -o integration-test-mode3 ./cmd/integration-test-mode3
ok "built aauth-service and integration-test-mode3"

sep "START STUB PS"
./integration-test-mode3 -mode ps -listen 127.0.0.1:9191 -resource-jwks "$HTTP_BASE/.well-known/jwks.json" >/tmp/mode3-ps.log 2>&1 &
PS_PID=$!
for _ in $(seq 1 30); do
  if curl -sf "$PS_BASE/.well-known/jwks.json" >/dev/null 2>&1; then
    ok "stub PS is serving JWKS"
    break
  fi
  sleep 1
done

sep "START RESOURCE"
AAUTH_CONFIG=demo/aauth-config-mode3.yaml ./aauth-service --port 17070 >/tmp/mode3-aauth.log 2>&1 &
AAUTH_PID=$!
for _ in $(seq 1 30); do
  if curl -sf "$HTTP_BASE/.well-known/aauth-resource.json" >/dev/null 2>&1; then
    ok "resource metadata is available"
    break
  fi
  sleep 1
done

sep "CHECK METADATA"
metadata=$(curl -sf "$HTTP_BASE/.well-known/aauth-resource.json")
echo "$metadata" | grep -q "\"authorization_endpoint\":\"$HTTP_BASE/resource/token\"" \
  && ok "authorization_endpoint defaults to /resource/token" \
  || fail "authorization_endpoint missing or incorrect"

sep "RUN MODE 3 FLOW"
if ./integration-test-mode3 -mode drive -grpc "$GRPC_ADDR" -ps "$PS_BASE" -resource-issuer "$HTTP_BASE" -resource-id mode3-demo -authority localhost -path /mode3; then
  ok "mode 3 round trip succeeded"
else
  fail "mode 3 round trip failed"
fi

sep "RESULTS"
echo "  Passed: $PASS  /  Failed: $FAIL"
[[ $FAIL -eq 0 ]]
