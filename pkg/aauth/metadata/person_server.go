package metadata

import "encoding/json"

type PersonServerMetadata struct {
	Issuer                 string   `json:"issuer"`
	TokenEndpoint          string   `json:"token_endpoint"`
	JwksURI                string   `json:"jwks_uri"`
	MissionEndpoint        string   `json:"mission_endpoint,omitempty"`
	PermissionEndpoint     string   `json:"permission_endpoint,omitempty"`
	AuditEndpoint          string   `json:"audit_endpoint,omitempty"`
	InteractionEndpoint    string   `json:"interaction_endpoint,omitempty"`
	MissionControlEndpoint string   `json:"mission_control_endpoint,omitempty"`
	LoginEndpoint          string   `json:"login_endpoint,omitempty"`
	RevocationEndpoint     string   `json:"revocation_endpoint,omitempty"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
	ClaimsSupported        []string `json:"claims_supported,omitempty"`
}

func BuildPersonServerMetadata(m *PersonServerMetadata) ([]byte, error) {
	return json.Marshal(m)
}
