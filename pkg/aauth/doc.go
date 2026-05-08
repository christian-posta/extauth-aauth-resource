// Package aauth implements the resource-side primitives of the AAuth protocol
// (Authenticated Authorization for autonomous agents).
//
// The package is split into a small resource-side surface — Verify, Identity,
// Challenge, MintResourceToken — and a set of focused sub-packages used by both
// resource servers and agent clients:
//
//   - [aauth-service/pkg/aauth/agent]       — agent SDK (signing, exchange, polling)
//   - [aauth-service/pkg/aauth/headers]     — AAuth-Requirement, Accept-Signature, etc.
//   - [aauth-service/pkg/aauth/http]        — 202/Deferred response helpers
//   - [aauth-service/pkg/aauth/identifiers] — AAuth server/agent identifier validation
//   - [aauth-service/pkg/aauth/keys]        — JWKS fetcher with caching, JWK conversion
//   - [aauth-service/pkg/aauth/metadata]    — well-known metadata documents and fetcher
//   - [aauth-service/pkg/aauth/transport]   — http.RoundTripper that signs requests
//
// Resource servers usually call [Verify] inside an extauthz adapter, then build
// a [Challenge] in the unauthenticated case. Implements AAuth SPEC §4 (token
// verification), §6 (signature verification) and §12 (challenge headers).
package aauth
