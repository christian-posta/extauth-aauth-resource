package httpsig

import (
	"fmt"
	"strings"
)

// RequestInfo contains the HTTP request elements needed for signature base construction.
type RequestInfo struct {
	Method    string
	Authority string
	Path      string // Includes query string
	Headers   map[string][]string
}

// NewResolver returns a ComponentResolver based on the RequestInfo.
func NewResolver(req RequestInfo) ComponentResolver {
	// Pre-process headers to be lower-case
	headers := make(map[string][]string)
	for k, v := range req.Headers {
		headers[strings.ToLower(k)] = v
	}

	return func(component string) (string, error) {
		comp := strings.ToLower(component)

		switch comp {
		case "@method":
			return req.Method, nil
		case "@authority":
			if req.Authority == "" {
				return "", fmt.Errorf("@authority is required but empty")
			}
			return req.Authority, nil
		case "@path":
			if req.Path == "" {
				return "", fmt.Errorf("@path is required but empty")
			}
			return req.Path, nil
		case "@target-uri", "@query", "@status":
			return "", fmt.Errorf("component %q is not supported", comp)
		}

		// Header field
		vals, ok := headers[comp]
		if !ok || len(vals) == 0 {
			return "", fmt.Errorf("missing header component %q", comp)
		}

		// RFC 9421 Section 2.1: Combine multiple header fields by concatenating with ", "
		var trimmedVals []string
		for _, v := range vals {
			trimmedVals = append(trimmedVals, strings.TrimSpace(v))
		}

		return strings.Join(trimmedVals, ", "), nil
	}
}
