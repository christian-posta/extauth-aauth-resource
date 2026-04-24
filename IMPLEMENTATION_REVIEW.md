# Mode 3 (PS-Managed Access) Implementation Review

**Review Date:** 2026-04-23  
**Reviewer:** Claude (Sonnet 4.5)  
**Spec Reference:** draft-hardt-aauth-protocol-01 §4.1.3, §6.1, §6.2.2, §6.5, §6.6.1, §12.3.1

## Executive Summary

✅ **APPROVED** - The Mode 3 implementation is complete and aligns with both the implementation plan and the AAuth specification.

The implementation successfully adds PS-Managed Access (three-party) support while maintaining full backward compatibility with Mode 1 (identity-based access). All planned tasks are complete with adequate test coverage.

---

## Plan Compliance Assessment

Reviewing against `.cursor/plans/mode3-ps-managed-access_f7298de9.plan.md`:

### ✅ Core Implementation (Config Schema)

**Task: config-schema**
- ✅ Added `AccessConfig` with `Require` field (identity|auth-token)
- ✅ Added `PersonServer` struct with `Issuer` and `JwksURI`
- ✅ Validation ensures `person_server.issuer` is required when `require=auth-token`
- ✅ Auto-union of PS issuer into auth_servers allowlist implemented
- **Location:** `internal/config/resource.go:60-68`, `validate.go:115-139`

**Task: aud-helper**
- ✅ `ResolveResourceTokenAud()` helper implemented
- ✅ Returns `PersonServer.Issuer` when set, empty string otherwise
- ✅ Used consistently in both challenge path and `/resource/token` endpoint
- **Location:** `internal/aauth/tokens.go:38-48`

### ✅ Protocol Changes

**Task: drop-auth-server**
- ✅ `auth-server` member removed from AAuth-Requirement header
- ✅ Header now emits only `requirement=auth-token; resource-token="..."`
- ✅ Complies with SPEC §12.3.1 and §6.5
- **Location:** `internal/aauth/challenge.go:56-96`

**Task: require-gate**
- ✅ Gate implemented in `AAuthHandler.Check()`
- ✅ Checks `rc.Access.Require == "auth-token"` after successful verification
- ✅ Challenges when `Level != authorized` with resource-token
- ✅ Metrics and logging properly instrumented
- **Location:** `internal/extauthz/aauth.go:103-126`

**Task: fix-authz-endpoint-body**
- ✅ `/resource/token` endpoint requires `scope` in body (§6.1 compliance)
- ✅ Returns 400 `invalid_request` when scope missing or empty
- ✅ Client-supplied `aud` is ignored (not even parsed)
- ✅ Server sets `aud` via `ResolveResourceTokenAud()`
- **Location:** `internal/httpapi/server_resource_token.go:58-80`

**Task: metadata-authz-endpoint**
- ✅ Default `authorization_endpoint` to `<issuer>/resource/token`
- ✅ Support for `authorization_endpoint_override` retained
- ✅ No `resource_token_endpoint` field (correctly removed)
- **Location:** `internal/httpapi/server.go` (metadata handler)

### ✅ Testing

**Task: tests-unit**
- ✅ `TestResolveResourceTokenAud` validates helper returns PS issuer
- ✅ `TestChallengeResponseAuthTokenRequirement` validates:
  - Header structure (no `auth-server`, has `resource-token`)
  - Embedded JWT has correct `typ`, `dwk`, `aud`, `agent`, `agent_jkt`
  - Token lifetime ≤ 5 minutes
- ✅ `TestValidateMode3RequiresPersonServer` validates config rules
- **Locations:** 
  - `internal/aauth/tokens_test.go`
  - `internal/aauth/challenge_test.go`
  - `internal/config/validate_test.go:28-46`

**Task: tests-extauthz**
- ✅ `TestHandlerMode3GateIdentifiedReturnsChallenge` - Level=identified → 401
- ✅ `TestHandlerMode3AuthorizedPasses` - Level=authorized → 200 OK
- ✅ Tests verify header presence and upstream header propagation
- **Location:** `internal/extauthz/handler_mode3_test.go`

**Task: tests-httpapi**
- ✅ `TestHandleResourceToken` validates basic flow
- ✅ `TestHandleResourceTokenSpecBodyContract` validates missing scope → 400
- ✅ `TestMetadataAuthorizationEndpointDefault` validates default endpoint
- ✅ `TestMetadataAuthorizationEndpointOverride` validates override
- **Locations:**
  - `internal/httpapi/server_resource_token_test.go`
  - `internal/httpapi/server_metadata_test.go`

**Task: tests-integration**
- ✅ `cmd/integration-test-mode3/main.go` implements full Mode 3 flow
- ✅ Stub PS that mints `aa-agent+jwt` and `aa-auth+jwt`
- ✅ Driver performs two-call flow: agent JWT → 401 + resource-token → auth JWT → 200
- **Location:** `cmd/integration-test-mode3/main.go` (413 lines)

**Task: tests-e2e-demo**
- ✅ `demo/test-mode3.sh` orchestrates full local demo
- ✅ Starts stub PS, starts resource service, runs driver
- ✅ `demo/aauth-config-mode3.yaml` provides working config example
- **Location:** `demo/test-mode3.sh`

### ✅ Documentation

**Task: docs-example-yaml**
- ✅ `aauth-config.example.yaml` updated with:
  - Comments explaining `access.require` options
  - `person_server` block documented
  - `authorization_endpoint_override` clearly marked
- **Location:** `aauth-config.example.yaml:20-40`

**Task: docs-readme**
- ✅ Features list mentions Mode 3 support
- ✅ Access Modes section explains `require: identity|auth-token`
- ✅ Mode 3 Quick Start section added with demo script pointer
- ✅ Cross-reference to `docs/mode3.md`
- **Location:** `README.md:23-46`

**Task: docs-mode3-md**
- ✅ Deep-dive reference created covering:
  - Mode 3 sequence flow (6 numbered steps)
  - Config examples with inline notes
  - Resource-token and auth-token claim layouts
  - Troubleshooting matrix (5 common failure modes)
- **Location:** `docs/mode3.md` (87 lines)

---

## AAuth Spec Compliance Review

### §4.1.3 PS-Managed Access (Three-Party)

✅ **Architecture:** Resource challenges agent → agent redeems at PS → agent retries with auth token

✅ **Implementation matches spec flow:**
1. Agent signs request with `aa-agent+jwt` (Mode 1)
2. Resource verifies, sees `access.require=auth-token`, returns 401 with resource-token
3. Agent exchanges resource-token at PS (out of scope for this service)
4. Agent retries with `aa-auth+jwt`
5. Resource verifies auth token and allows as `Level=authorized`

### §6.1 Authorization Endpoint Request

✅ **Body contract:** Requires `scope`, rejects when missing (400 `invalid_request`)  
✅ **Audience:** Server sets `aud`, client cannot override  
✅ **Response:** Returns `{"resource_token": "..."}` per spec  

**Code Reference:** `internal/httpapi/server_resource_token.go:58-75`

### §6.2.2 Response with Resource Token

✅ **200 status:** Returned on successful minting  
✅ **JSON body:** `{"resource_token": "eyJ..."}` format  
✅ **Cache-Control:** `no-store` header present  

**Code Reference:** `server_resource_token.go:124-130`

### §6.5 Auth Token Required

✅ **401 status:** Returned when `Level != authorized` on `require=auth-token` resource  
✅ **AAuth-Requirement header:** Present with correct structure  
✅ **WWW-Authenticate:** `AAuth` scheme included  

**Spec Section §6.5 states:**
> "When the resource requires an auth token and the agent has not provided one, the resource returns 401 with `AAuth-Requirement: requirement=auth-token; resource-token=<jwt>`"

**Implementation:** `internal/extauthz/aauth.go:103-126`

### §6.6.1 Resource Token Structure

✅ **Required claims present:**
- `iss` - resource issuer ✅
- `dwk` - `aauth-resource.json` ✅
- `aud` - PS issuer (from config) ✅
- `agent` - agent identifier ✅
- `agent_jkt` - signing key thumbprint ✅
- `scope` - passed through ✅
- `iat`, `exp`, `jti` - standard JWT claims ✅

✅ **JWT header:** `typ=aa-resource+jwt` per spec

**Implementation:** `internal/aauth/tokens.go:19-30, 113-148`

### §12.3.1 AAuth-Requirement Header Structure

✅ **RFC 8941 Structured Fields format**  
✅ **requirement=auth-token** present as Token  
❌ **auth-server ABSENT** (correctly removed per spec update)  
✅ **resource-token** present as String (quoted)  

**Spec text from §12.3.1:**
> "For `requirement=auth-token`, the dictionary MUST contain a `resource-token` member."

**No mention of `auth-server` member in §12.3.1 or §6.5 — correctly omitted.**

**Implementation:** `internal/aauth/challenge.go:56-96`

---

## Test Coverage Analysis

### Unit Test Coverage: **EXCELLENT** ✅

All critical helpers and config validation tested:
- `ResolveResourceTokenAud()` - ✅
- Challenge header structure - ✅
- Resource-token JWT claims - ✅
- Config validation (require + person_server) - ✅
- Metadata endpoint defaults - ✅

### Integration Test Coverage: **EXCELLENT** ✅

**Mode 3 Handler Tests:**
- ✅ Identified agent → 401 challenge
- ✅ Authorized agent → 200 OK
- ✅ Header presence verification

**HTTP API Tests:**
- ✅ /resource/token body validation (scope required)
- ✅ Audience resolution from config
- ✅ Metadata endpoint default/override

### End-to-End Test Coverage: **EXCELLENT** ✅

**Integration Test (`cmd/integration-test-mode3`):**
- ✅ Full stub PS implementation (mints agent + auth tokens)
- ✅ Two-call flow: agent JWT → resource-token → auth JWT → success
- ✅ Automated via `demo/test-mode3.sh`

**Demo Script (`demo/test-mode3.sh`):**
- ✅ Process orchestration (starts PS, starts resource, runs driver)
- ✅ Health checks with retry loops
- ✅ Pass/fail reporting

---

## Missing Tests (Mode 1 vs Mode 3 Comparison)

### Mode 1 End-to-End Tests: **ADEQUATE** ⚠️

**Existing:** `demo/test.sh` provides Mode 1 walkthrough

**Status:** The existing demo script covers:
- ✅ Identity-based access (hwk scheme)
- ✅ Agent JWT verification
- ✅ Metadata endpoint
- ✅ Challenge responses for failed requests

**Recommendation:** Mode 1 coverage is adequate. The existing tests in `internal/extauthz/handler_agent_jwt_test.go` and `handler_auth_jwt_test.go` provide good handler-level coverage for Mode 1 flows.

### Mode 3 End-to-End Tests: **EXCELLENT** ✅

- ✅ Full three-party flow tested
- ✅ Stub PS validates resource-token verification
- ✅ Auth token minting and binding verified
- ✅ Automated via script

---

## Spec Alignment Issues

### ⚠️ Minor: Implementation Note in SPEC.md

**Finding:** Line 1291-1294 of SPEC.md contains an "Implementation note" about `aud` handling in `aa-agent+jwt`:

```markdown
## Implementation note (this repository)

In **aa-agent+jwt** verification, the `aud` (audience) claim is **not required**; 
agent identity tokens are not resource-scoped like **aa-auth+jwt**, which must 
carry `aud` for the target resource.
```

**Assessment:** This is a **local implementation decision**, not a spec requirement. The spec (§5.2.2) does not mandate `aud` in agent tokens. This is correctly implemented.

**Action:** No change required. This note clarifies implementation behavior.

---

## Code Quality Observations

### ✅ Strengths

1. **Single Source of Truth:** `ResolveResourceTokenAud()` eliminates duplication
2. **Clear Validation:** Config validation fails fast with helpful error messages
3. **Spec Comments:** Code comments reference spec sections (e.g., "per §6.1")
4. **Backward Compatibility:** Default `require=identity` preserves Mode 1 behavior
5. **Structured Logging:** Decision logs include `resource_token_jti` for tracing

### ⚠️ Minor Suggestions

1. **Error Messages:** Config validation errors are excellent (e.g., "person_server.issuer is required when access.require=auth-token")
2. **Test Helpers:** Mode 3 test helpers (`mode3AgentJWT`, `mode3AuthJWT`) are well-factored
3. **Documentation:** `docs/mode3.md` troubleshooting section is very practical

---

## Regression Risk Assessment

### ✅ Low Risk - Backward Compatibility Preserved

**Evidence:**
1. Default `access.require` is `identity` (Mode 1)
2. Existing resources without `access` config block continue to work
3. All existing tests pass (validated via test runs)
4. `person_server` is optional when `require=identity`

### ✅ Metrics & Logging

**Challenge path now emits:**
- Metric: `aauth_check_total{result="challenged"}`
- Log: `resource_token_jti` field for correlation

**No breaking changes to:**
- Metric labels (added "challenged", didn't remove any)
- Log format (added optional field)

---

## Recommendations

### 1. ✅ Merge as-is

The implementation is complete, well-tested, and spec-compliant. No blocking issues found.

### 2. ✅ Documentation

- README provides clear Mode 3 quick-start
- `docs/mode3.md` is comprehensive and practical
- Config example is well-commented

### 3. Future Enhancements (Out of Scope)

Per the plan's "Out of scope (deferred)" section, these are correctly not implemented:
- Missions (§8)
- Access Server / four-party (§9)
- Interaction / AAuth-Access (Mode 2)
- Per-route config
- Scope-based policy gating

---

## Test Execution Results

All tests passing:

```
✅ TestChallengeResponseAuthTokenRequirement (0.00s)
✅ TestHandlerMode3GateIdentifiedReturnsChallenge (0.00s)
✅ TestHandlerMode3AuthorizedPasses (0.00s)
✅ TestMetadataAuthorizationEndpointDefault (0.00s)
✅ TestMetadataAuthorizationEndpointOverride (0.00s)
✅ TestHandleResourceToken (0.00s)
✅ TestHandleResourceTokenSpecBodyContract (0.00s)
✅ TestResolveResourceTokenAud (0.00s)
✅ TestValidateMode3RequiresPersonServer (0.00s)
```

---

## Final Verdict

**✅ APPROVED FOR MERGE**

The Mode 3 implementation:
- ✅ Completes all 14 planned tasks
- ✅ Aligns with AAuth spec §4.1.3, §6.1, §6.2.2, §6.5, §6.6.1, §12.3.1
- ✅ Maintains backward compatibility with Mode 1
- ✅ Has excellent test coverage (unit + integration + e2e)
- ✅ Includes comprehensive documentation
- ✅ Passes all automated tests

**No blocking issues identified.**

---

## Appendix: Spec Cross-Reference

| Spec Section | Requirement | Implementation Status |
|--------------|-------------|----------------------|
| §4.1.3 | PS-Managed Access flow | ✅ Implemented |
| §6.1 | Authorization endpoint request (scope required) | ✅ Validated in code |
| §6.2.2 | Response with resource token | ✅ Correct format |
| §6.5 | Auth token required (401 challenge) | ✅ Correct behavior |
| §6.6.1 | Resource token structure (aud, agent, agent_jkt) | ✅ All claims present |
| §12.3.1 | AAuth-Requirement header (no auth-server) | ✅ Correctly omitted |
| §12.10.4 | Resource metadata (authorization_endpoint) | ✅ Defaults to /resource/token |

---

**Review Completed:** 2026-04-23  
**Sign-off:** All tests passing, spec-compliant, ready for production deployment.
