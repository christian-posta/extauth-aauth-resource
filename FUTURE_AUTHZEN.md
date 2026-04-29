# Future AuthZEN Support

This note captures a possible path for supporting OpenID AuthZEN Authorization API 1.0 alongside the existing Envoy/AgentGateway `ext_authz` integration.

## Summary

AuthZEN is similar to `ext_authz` at the architectural level: both are Policy Enforcement Point (PEP) to Policy Decision Point (PDP) authorization protocols. They are not wire-compatible.

`ext_authz` is a proxy integration protocol. Envoy or AgentGateway sends request attributes and expects a protocol-specific allow/deny response that can mutate upstream headers, remove request headers, return custom downstream responses, and emit dynamic metadata.

AuthZEN is a JSON authorization API. A PEP sends `subject`, `resource`, `action`, and optional `context`; the PDP returns a JSON decision:

```json
{
  "decision": true
}
```

Denied authorization is still a successful AuthZEN API response:

```json
{
  "decision": false
}
```

That means AuthZEN cannot directly replace `ext_authz` for Envoy/AgentGateway. It can be supported as an inbound API that a compatible PEP calls, provided the PEP understands an AAuth-specific profile carried in AuthZEN request and response context.

## Recommended Positioning

Do not present AuthZEN as a replacement for `ext_authz`.

Recommended positioning:

> This service supports Envoy/AgentGateway `ext_authz` for AAuth enforcement. It may also expose an AuthZEN-compatible inbound API for PEPs that want to request AAuth resource enforcement decisions over the OpenID AuthZEN Authorization API.

In other words, AuthZEN support should be treated as an AAuth resource-enforcement profile over AuthZEN.

## Key Constraint

AAuth resource behavior requires fine-grained response control:

- return `401 Unauthorized`
- return `AAuth-Requirement`
- include a signed `resource-token`
- return `WWW-Authenticate: AAuth`
- return `Signature-Error`
- return `Accept-Signature`
- add upstream identity headers
- remove signature headers before upstream forwarding
- expose dynamic metadata or its equivalent

AuthZEN does not define native equivalents for all of those proxy behaviors. It does, however, allow arbitrary structured response `context`, which can carry AAuth-specific enforcement instructions.

A generic AuthZEN PEP may only understand `decision=true` or `decision=false`. A PEP must understand this project's AAuth/AuthZEN profile to translate response context into real HTTP status, headers, body, and metadata.

## Architecture

The cleanest architecture is to extract current AAuth handling into a protocol-neutral enforcement core and place adapters on top.

Current shape:

```text
ext_authz CheckRequest
  -> AAuth verification
  -> Mode 1 / Mode 3 gate
  -> policy.Engine
  -> ext_authz CheckResponse
```

Target shape:

```text
ext_authz adapter
  -> AAuth enforcement core
  -> ext_authz response

AuthZEN adapter
  -> AAuth enforcement core
  -> AuthZEN decision response
```

The policy engine should remain one stage inside the AAuth enforcement core, after AAuth identity/auth-token verification has produced an identity.

The AAuth enforcement core should own AAuth protocol behavior. Adapters should only translate transport-specific request and response shapes.

## Protocol-Neutral Core Sketch

A future core API could look like this:

```go
type EnforcementRequest struct {
    ResourceID string
    Method     string
    Authority  string
    Path       string
    Headers    map[string][]string
    Body       []byte
    Context    map[string]any
}

type EnforcementDecision struct {
    Allow           bool
    StatusCode      int
    ResponseHeaders map[string]string
    ResponseBody    []byte
    UpstreamHeaders map[string]string
    HeadersToRemove []string
    Metadata        map[string]any
    Reason          string
}
```

The `ext_authz` adapter would convert `EnforcementDecision` into:

- `CheckResponse.Status`
- `DeniedHttpResponse`
- `OkHttpResponse`
- upstream header mutations
- `HeadersToRemove`
- `DynamicMetadata`

The AuthZEN adapter would convert `EnforcementDecision` into:

- top-level `decision`
- `context.aauth.response`
- `context.aauth.metadata`
- `context.aauth.upstream`

## AuthZEN Request Profile

AuthZEN does not define a standard HTTP request envelope for method, authority, path, headers, and body. An AAuth profile should define one under `context.http`.

Example:

```json
{
  "subject": {
    "type": "request",
    "id": "unknown"
  },
  "resource": {
    "type": "aauth-resource",
    "id": "mcp-api"
  },
  "action": {
    "name": "http.request"
  },
  "context": {
    "http": {
      "method": "GET",
      "authority": "api.example.com",
      "path": "/mcp",
      "headers": {
        "signature": ["..."],
        "signature-input": ["..."],
        "signature-key": ["..."]
      },
      "body_base64": "..."
    }
  }
}
```

Notes:

- `resource.id` can map to the existing resource id, similar to `aauth_resource_id` in `ext_authz` context extensions.
- `context.http.authority` should be the value used for RFC 9421 `@authority`.
- `context.http.headers` should preserve repeated header values.
- `body_base64` should be optional and only required if a resource requires body-bound signature components.
- For unsigned first calls, AuthZEN still requires `subject`; use a placeholder such as `type=request`, `id=unknown`.
- For valid signed calls, the actual AAuth identity should be derived by the service and returned in response context.

## AuthZEN Response Profile

For an allowed request:

```json
{
  "decision": true,
  "context": {
    "aauth": {
      "metadata": {
        "level": "authorized",
        "scheme": "jwt",
        "token_type": "aa-auth+jwt",
        "agent": "aauth:local@agents.example.com",
        "sub": "pairwise-user-id",
        "scope": "mcp:invoke",
        "act": {
          "sub": "aauth:local@agents.example.com"
        }
      },
      "upstream": {
        "headers": {
          "x-aauth-level": "authorized",
          "x-aauth-agent-server": "aauth:local@agents.example.com",
          "x-aauth-delegate": "pairwise-user-id",
          "x-aauth-scope": "mcp:invoke"
        },
        "headers_to_remove": [
          "signature",
          "signature-input",
          "signature-key"
        ]
      }
    }
  }
}
```

For a Mode 3 challenge:

```json
{
  "decision": false,
  "context": {
    "aauth": {
      "response": {
        "status": 401,
        "headers": {
          "AAuth-Requirement": "requirement=auth-token; resource-token=\"...\"",
          "WWW-Authenticate": "AAuth",
          "Content-Type": "application/json"
        },
        "body": {
          "error": "insufficient_scope"
        }
      },
      "metadata": {
        "level": "identified",
        "scheme": "jwt",
        "token_type": "aa-agent+jwt",
        "agent_server": "https://agents.example.com",
        "sub": "aauth:agent@agents.example.com"
      }
    }
  }
}
```

For a missing or invalid signature:

```json
{
  "decision": false,
  "context": {
    "aauth": {
      "response": {
        "status": 401,
        "headers": {
          "AAuth-Requirement": "requirement=auth-token",
          "WWW-Authenticate": "AAuth",
          "Signature-Error": "error=invalid_signature",
          "Accept-Signature": "sig1=(\"@method\" \"@authority\" \"@path\");sigkey=jkt",
          "Content-Type": "application/json"
        },
        "body": {
          "error": "missing_signature"
        }
      }
    }
  }
}
```

## Dynamic Metadata Equivalent

AuthZEN does not have Envoy dynamic metadata. The equivalent should be structured response context:

```json
{
  "context": {
    "aauth": {
      "metadata": {
        "level": "authorized",
        "scheme": "jwt",
        "token_type": "aa-auth+jwt",
        "issuer": "https://ps.example.com",
        "agent": "aauth:local@agents.example.com",
        "sub": "pairwise-user-id",
        "scope": "mcp:invoke",
        "txn": "txn-123",
        "act": {
          "sub": "aauth:local@agents.example.com"
        }
      }
    }
  }
}
```

For the `ext_authz` adapter, the same metadata becomes `CheckResponse.dynamic_metadata`.

For the AuthZEN adapter, it remains in `context.aauth.metadata`.

## Discovery

AuthZEN metadata is published at:

```text
/.well-known/authzen-configuration
```

A minimal metadata response could be:

```json
{
  "policy_decision_point": "https://resource.example.com",
  "access_evaluation_endpoint": "https://resource.example.com/access/v1/evaluation",
  "capabilities": [
    "urn:authzen:capability:aauth-resource"
  ]
}
```

If the capability URN is not registered, use a project-specific URN initially, for example:

```text
urn:christian-posta:aauth:authzen:resource
```

or:

```text
urn:extauth-aauth-resource:capability:aauth-resource
```

Do not publish search endpoints unless they are actually implemented.

## Proposed Implementation Order

1. Extract current `ext_authz` AAuth request handling into a protocol-neutral enforcement core.
2. Keep current `ext_authz` behavior equivalent through a thin adapter.
3. Add `POST /access/v1/evaluation` as an AuthZEN adapter.
4. Add `GET /.well-known/authzen-configuration`.
5. Document the AAuth/AuthZEN profile:
   - `context.http`
   - `context.aauth.response`
   - `context.aauth.metadata`
   - `context.aauth.upstream`
6. Add conformance-style tests for:
   - unsigned request challenge
   - pseudonymous allowed request
   - identified Mode 3 challenge with `resource-token`
   - authorized Mode 3 allow
   - invalid signature diagnostics
   - request id echoing via `X-Request-ID`
7. Defer AuthZEN search APIs until there is a real use case.

## Open Questions

- Should `subject` be required to reflect the caller-provided identity, or should this service always derive identity from AAuth and return it in response context?
- Should `resource.id` always map to configured resource id, or should host-based lookup be supported via `context.http.authority`?
- Should response `context.aauth.response.headers` be an object of string values or an object of string arrays?
- Should the profile allow body forwarding directly, or only body digests, to avoid large AuthZEN requests?
- Should AuthZEN support be enabled per resource or globally on the HTTP listener?

## Recommendation

AuthZEN support is feasible and useful if implemented as an explicit AAuth profile over AuthZEN.

The project should preserve `ext_authz` as the primary gateway integration and use a shared AAuth enforcement core to keep behavior consistent across adapters. This keeps AAuth protocol response control intact while allowing non-Envoy PEPs to call the same resource-side enforcement logic over a standards-based JSON API.
