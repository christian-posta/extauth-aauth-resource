package headers

import (
	"fmt"
	"strings"
)

// Capabilities represents the parsed value of an AAuth-Capabilities request header.
// The agent declares which optional interaction channels it supports.
type Capabilities struct {
	// Interaction indicates the agent can handle user interaction flows.
	Interaction bool
	// Clarification indicates the agent can handle clarification requests.
	Clarification bool
	// Payment indicates the agent can handle payment flows.
	Payment bool
}

// ParseCapabilities parses an AAuth-Capabilities header value.
//
// The header value is a comma-separated list of capability tokens.
func ParseCapabilities(headerValue string) (*Capabilities, error) {
	if strings.TrimSpace(headerValue) == "" {
		return nil, fmt.Errorf("AAuth-Capabilities: empty header value")
	}

	c := &Capabilities{}
	for _, tok := range strings.Split(headerValue, ",") {
		switch strings.TrimSpace(tok) {
		case "interaction":
			c.Interaction = true
		case "clarification":
			c.Clarification = true
		case "payment":
			c.Payment = true
		}
	}
	return c, nil
}

// BuildCapabilities serializes a Capabilities struct into a comma-separated
// token list suitable for use as an AAuth-Capabilities header value.
func BuildCapabilities(c *Capabilities) (string, error) {
	if c == nil {
		return "", fmt.Errorf("BuildCapabilities: nil Capabilities")
	}

	var parts []string
	if c.Interaction {
		parts = append(parts, "interaction")
	}
	if c.Clarification {
		parts = append(parts, "clarification")
	}
	if c.Payment {
		parts = append(parts, "payment")
	}

	return strings.Join(parts, ", "), nil
}
