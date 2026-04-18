package httpsig

import (
	"fmt"
	"strings"

	"policy_engine/pkg/httpsig/structfields"
)

// ComponentResolver extracts the value of a signature component from the request.
type ComponentResolver func(component string) (string, error)

// BuildSignatureBase constructs the RFC 9421 signature base string.
func BuildSignatureBase(covered []string, params structfields.Params, resolver ComponentResolver) (string, error) {
	var sb strings.Builder

	// Add each covered component
	for _, comp := range covered {
		val, err := resolver(comp)
		if err != nil {
			return "", fmt.Errorf("failed to resolve component %q: %w", comp, err)
		}

		// Ensure component identifier is properly serialized
		// In a full implementation we'd handle component parameters like ;req or ;bs here.
		sb.WriteString(fmt.Sprintf("\"%s\": %s\n", comp, val))
	}

	// Add the signature parameters
	sb.WriteString("\"@signature-params\": ")

	// Serialize the inner list of covered components and the parameters
	// According to RFC 9421, the signature parameters are an Inner List.
	items := make([]structfields.Item, len(covered))
	for i, c := range covered {
		items[i] = structfields.Item{Value: c} // String value for component names
	}

	innerList := structfields.InnerList{
		Items:  items,
		Params: params,
	}

	serializedParams, err := structfields.SerializeList(structfields.List{innerList})
	if err != nil {
		return "", fmt.Errorf("failed to serialize signature parameters: %w", err)
	}

	sb.WriteString(serializedParams)

	return sb.String(), nil
}
