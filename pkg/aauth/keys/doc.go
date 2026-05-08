// Package keys provides JWKS retrieval with caching and helpers for converting
// between Go crypto types and JWKs.
//
// [JWKSFetcher] caches JWK Sets keyed by jwks_uri with bounded TTLs and a
// minimum re-fetch interval (rate-limiting key rotation polls). It implements
// the SPEC §5.5 key-discovery rules used during signature and JWT verification.
//
// [Ed25519PublicKeyToJWK], [JWKToEd25519PublicKey] and [Thumbprint] cover the
// most common JWK conversions agents and resource servers need.
package keys
