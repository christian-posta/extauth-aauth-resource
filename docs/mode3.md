# Mode 3 (PS-Managed Access)

Mode 3 is the three-party AAuth flow where the resource challenges an identified agent, the agent redeems the returned resource-token at its Person Server, and then retries with an `aa-auth+jwt`.

## Sequence

1. The agent calls the resource with a valid Mode 1 request, typically signed with `aa-agent+jwt`.
2. The resource verifies the request, sees `access.require: auth-token`, and returns:
   `AAuth-Requirement: requirement=auth-token; resource-token="..."`
3. The agent redeems that `aa-resource+jwt` at its Person Server.
4. The Person Server returns an `aa-auth+jwt` with:
   `iss=<person server>`
   `aud=<resource issuer>`
   `act.sub=<agent signing key thumbprint>`
5. The agent retries the original request, signed with the same key and carrying the `aa-auth+jwt`.
6. The resource verifies the auth token and allows the request as `authorized`.

## Resource Config

```yaml
resources:
  - id: mode3-demo
    issuer: http://127.0.0.1:18090
    signing_key:
      kid: mode3-demo-key
      alg: EdDSA
      private_key_file: demo/resource_key.pem

    access:
      require: auth-token

    person_server:
      issuer: http://127.0.0.1:9191
      jwks_uri: http://127.0.0.1:9191/.well-known/jwks.json

    agent_servers:
      - issuer: http://127.0.0.1:9191
        jwks_uri: http://127.0.0.1:9191/.well-known/jwks.json
```

Notes:

- `access.require: identity` is still Mode 1 and remains the default.
- `person_server.issuer` is required only when `access.require: auth-token`.
- `person_server.issuer` is automatically added to the resource's accepted auth-server allowlist.
- Metadata now defaults `authorization_endpoint` to `<issuer>/resource/token`.

## Claims

The resource-token minted by the challenge path contains:

- `iss`: the resource issuer
- `dwk`: `aauth-resource.json`
- `aud`: the configured `person_server.issuer`
- `agent`: the agent identifier from the presented Mode 1 identity
- `agent_jkt`: the signing-key thumbprint the follow-up auth token must bind to
- `scope`: propagated scope context when available
- `iat`, `exp`, `jti`

The returned auth token is expected to contain:

- `iss`: the Person Server issuer
- `dwk`: `aauth-access.json`
- `aud`: the resource issuer
- `sub`: the delegated agent identity
- `agent`: an agent platform URL
- `act.sub`: the same thumbprint as the request signing key
- `cnf.jwk`: the public key used to sign the follow-up request

## Demo

Run the local stub-PS demo:

```bash
bash demo/test-mode3.sh
```

That script starts a stub Person Server, starts the resource service with [demo/aauth-config-mode3.yaml](../demo/aauth-config-mode3.yaml), then runs [cmd/integration-test-mode3/main.go](../cmd/integration-test-mode3/main.go) as a driver.

## Troubleshooting

- `401` with no `resource-token`: the initial request did not establish agent key material, so the resource had nothing to bind.
- `person_server.issuer is required`: the resource is configured for `auth-token` but missing the pinned Person Server.
- `audience mismatch`: the Person Server minted the wrong `aud`; the auth token must target the resource issuer.
- `act.sub must match cnf.jwk thumbprint`: the follow-up request was not signed by the same key the auth token binds to.
- `issuer is not a configured auth server`: the resource does not trust the Person Server issuer for `aa-auth+jwt` verification.
