package metadata

import "encoding/json"

type AuthServerMetadata struct {
	Issuer              string `json:"issuer"`
	TokenEndpoint       string `json:"token_endpoint"`
	JwksURI             string `json:"jwks_uri"`
	InteractionEndpoint string `json:"interaction_endpoint,omitempty"`
	LoginEndpoint       string `json:"login_endpoint,omitempty"`
	RevocationEndpoint  string `json:"revocation_endpoint,omitempty"`
}

func BuildAuthServerMetadata(m *AuthServerMetadata) ([]byte, error) {
	return json.Marshal(m)
}
