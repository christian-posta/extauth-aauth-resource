// Package headers parses and serializes the AAuth-specific HTTP headers
// defined in AAuth SPEC §12.3 and §12.4.
//
// Resource servers build challenges with [BuildAAuthRequirement] and
// [BuildAcceptSignature]; agents read them with [ParseAAuthRequirement] and
// [ParseAcceptSignature]. [SignatureError] models the Signature-Error response
// header from draft-hardt-httpbis-signature-key; [Mission] and [Capabilities]
// model the AAuth-Mission and AAuth-Capabilities request headers (SPEC §8).
//
// All header values use RFC 8941 Structured Field syntax via
// aauth-service/pkg/httpsig/structfields.
package headers
