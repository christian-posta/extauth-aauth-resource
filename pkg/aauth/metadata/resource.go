package metadata

import "encoding/json"

// ResourceMetadata represents the resource metadata document published at
// /.well-known/aauth-resource.json per AAuth spec §12.10.2.
type ResourceMetadata struct {
	// Resource (issuer) is the resource's HTTPS URL — REQUIRED.
	Resource string `json:"issuer"`
	// AuthorizationEndpoint is the URL where agents request authorization — OPTIONAL.
	AuthorizationEndpoint string `json:"authorization_endpoint,omitempty"`
	// JwksURI is the URL to the resource's JSON Web Key Set — REQUIRED.
	JwksURI string `json:"jwks_uri,omitempty"`
	// AdditionalSignatureComponents lists extra HTTP message component identifiers
	// agents MUST include in covered components — OPTIONAL.
	AdditionalSignatureComponents []string `json:"additional_signature_components,omitempty"`
	// SupportedScopes lists the scope values this resource recognises — OPTIONAL.
	SupportedScopes []string `json:"supported_scopes,omitempty"`
	// ScopeDescriptions maps scope values to human-readable Markdown strings — OPTIONAL.
	ScopeDescriptions map[string]string `json:"scope_descriptions,omitempty"`
	// SignatureWindow is the signature validity window in seconds for the
	// created timestamp — OPTIONAL (default 60).
	SignatureWindow int `json:"signature_window,omitempty"`
	// ClientName is a human-readable resource name per RFC 7591 — OPTIONAL.
	ClientName string `json:"client_name,omitempty"`
	// LogoURI is the URL to the resource logo — OPTIONAL.
	LogoURI string `json:"logo_uri,omitempty"`
	// LogoDarkURI is the URL to the resource logo for dark backgrounds — OPTIONAL.
	LogoDarkURI string `json:"logo_dark_uri,omitempty"`
	// LoginEndpoint is the URL for third-party login initiation per spec §11 — OPTIONAL.
	LoginEndpoint string `json:"login_endpoint,omitempty"`
	// RevocationEndpoint is the URL where authorized parties can revoke auth tokens — OPTIONAL.
	RevocationEndpoint string `json:"revocation_endpoint,omitempty"`
	// ResourceTokenEndpoint is a legacy URL for proactive resource token requests — OPTIONAL.
	ResourceTokenEndpoint string `json:"resource_token_endpoint,omitempty"`
}

// BuildResourceMetadata marshals a ResourceMetadata into JSON bytes.
func BuildResourceMetadata(m *ResourceMetadata) ([]byte, error) {
	return json.Marshal(m)
}
