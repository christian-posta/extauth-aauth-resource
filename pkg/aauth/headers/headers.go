package headers

// Header field name constants for AAuth and related HTTP headers.
const (
	// HeaderAAuthRequirement is the AAuth-Requirement response header (RFC 8941 Dictionary).
	HeaderAAuthRequirement = "aauth-requirement"
	// HeaderAcceptSignature is the Accept-Signature response header per draft-hardt-httpbis-signature-key.
	HeaderAcceptSignature = "accept-signature"
	// HeaderSignatureError is the Signature-Error response header per draft-hardt-httpbis-signature-key.
	HeaderSignatureError = "signature-error"
	// HeaderAAuthMission is the AAuth-Mission request header per spec §8.7.
	HeaderAAuthMission = "aauth-mission"
	// HeaderAAuthCapabilities is the AAuth-Capabilities request header.
	HeaderAAuthCapabilities = "aauth-capabilities"
)
