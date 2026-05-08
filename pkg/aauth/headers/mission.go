package headers

import (
	"fmt"

	"aauth-service/pkg/httpsig/structfields"
)

// Mission represents the parsed value of an AAuth-Mission request header (spec §8.7).
//
// The agent includes this header when operating in a mission context, signalling
// that it has a person server and that an approved mission document governs the
// interaction.
type Mission struct {
	// ID is an optional mission identifier (not in the wire header; derived from context).
	ID string
	// Approver is the HTTPS URL of the entity that approved the mission.
	Approver string
	// Hash is the base64url-encoded SHA-256 hash (s256) of the approved mission JSON.
	Hash string
}

// ParseMission parses an AAuth-Mission header value (RFC 8941 Dictionary).
//
// The SPEC (§8.7) shows two serialisation styles for this header:
//   - RFC 8941 Dictionary with comma-separated members: approver="url", s256="hash"
//   - RFC 8941 Dictionary where s256 is a parameter on the approver item:
//     approver="url"; s256="hash"
//
// Both styles are supported.
func ParseMission(headerValue string) (*Mission, error) {
	dict, err := structfields.ParseDictionary(headerValue)
	if err != nil {
		return nil, fmt.Errorf("AAuth-Mission: invalid structured field: %w", err)
	}

	m := &Mission{}

	// Check approver as a top-level dictionary key first.
	if v, ok := dict.Get("approver"); ok {
		if item, ok := v.(structfields.Item); ok {
			if s, ok := item.Value.(string); ok {
				m.Approver = s
			}
			// s256 may appear as a parameter on the approver item (spec §8.7 style).
			if s256Val, ok := item.Params.Get("s256"); ok {
				if s, ok := s256Val.(string); ok {
					m.Hash = s
				}
			}
		}
	}
	// Support legacy "manager" key for backward compatibility with early implementations.
	if m.Approver == "" {
		if v, ok := dict.Get("manager"); ok {
			if item, ok := v.(structfields.Item); ok {
				if s, ok := item.Value.(string); ok {
					m.Approver = s
				}
				if s256Val, ok := item.Params.Get("s256"); ok {
					if s, ok := s256Val.(string); ok {
						m.Hash = s
					}
				}
			}
		}
	}

	// Also check s256 as a top-level dictionary key (comma-separated style).
	if m.Hash == "" {
		if v, ok := dict.Get("s256"); ok {
			if item, ok := v.(structfields.Item); ok {
				if s, ok := item.Value.(string); ok {
					m.Hash = s
				}
			}
		}
	}

	if m.Approver == "" {
		return nil, fmt.Errorf("AAuth-Mission: missing 'approver' parameter")
	}
	if m.Hash == "" {
		return nil, fmt.Errorf("AAuth-Mission: missing 's256' parameter")
	}

	return m, nil
}

// BuildMission serializes a Mission into an RFC 8941 Dictionary header value.
func BuildMission(m *Mission) (string, error) {
	if m == nil {
		return "", fmt.Errorf("BuildMission: nil Mission")
	}
	if m.Approver == "" {
		return "", fmt.Errorf("BuildMission: Approver must not be empty")
	}
	if m.Hash == "" {
		return "", fmt.Errorf("BuildMission: Hash must not be empty")
	}

	dict := structfields.Dictionary{
		{Name: "approver", Value: structfields.Item{Value: m.Approver}},
		{Name: "s256", Value: structfields.Item{Value: m.Hash}},
	}

	return structfields.SerializeDictionary(dict)
}
