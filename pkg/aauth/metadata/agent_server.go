package metadata

import "encoding/json"

type AgentServerMetadata struct {
	Issuer                   string `json:"issuer"`
	JwksURI                  string `json:"jwks_uri,omitempty"`
	ClientName               string `json:"client_name,omitempty"`
	LogoURI                  string `json:"logo_uri,omitempty"`
	LogoDarkURI              string `json:"logo_dark_uri,omitempty"`
	CallbackEndpoint         string `json:"callback_endpoint,omitempty"`
	LoginEndpoint            string `json:"login_endpoint,omitempty"`
	LocalhostCallbackAllowed *bool  `json:"localhost_callback_allowed,omitempty"`
	ClarificationSupported   *bool  `json:"clarification_supported,omitempty"`
	TosURI                   string `json:"tos_uri,omitempty"`
	PolicyURI                string `json:"policy_uri,omitempty"`
}

func BuildAgentServerMetadata(m *AgentServerMetadata) ([]byte, error) {
	return json.Marshal(m)
}
