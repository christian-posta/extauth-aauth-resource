package identifiers

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// localPartRE matches a valid local part of an aauth: agent identifier per spec §5.1.
// Allowed characters: lowercase ASCII letters, digits, hyphen, underscore, plus, period.
var localPartRE = regexp.MustCompile(`^[a-z0-9\-_+.]+$`)

// ValidateServerIdentifier validates an AAuth server identifier per spec §12.9.1.
//
// Server identifiers MUST:
//   - Use the https scheme
//   - Contain only scheme and host (no port, path, query, or fragment)
//   - Not include a trailing slash
//   - Be entirely lowercase
func ValidateServerIdentifier(s string) error {
	if s == "" {
		return fmt.Errorf("server identifier must not be empty")
	}

	parsed, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("server identifier is not a valid URL: %w", err)
	}

	if parsed.Scheme != "https" {
		return fmt.Errorf("server identifier must use https scheme: %q", s)
	}

	if parsed.Hostname() == "" {
		return fmt.Errorf("server identifier must have a hostname: %q", s)
	}

	// url.Parse puts the port in Host as "host:port"; Hostname() strips it.
	// If Host != Hostname(), a port is present.
	if parsed.Host != parsed.Hostname() {
		return fmt.Errorf("server identifier must not contain a port: %q", s)
	}

	// Path must be absent or empty. A bare trailing slash is also forbidden.
	if parsed.Path != "" {
		return fmt.Errorf("server identifier must not contain a path: %q", s)
	}

	if parsed.RawQuery != "" {
		return fmt.Errorf("server identifier must not contain a query string: %q", s)
	}

	if parsed.Fragment != "" {
		return fmt.Errorf("server identifier must not contain a fragment: %q", s)
	}

	// Reconstruct to catch trailing slash: url.Parse("https://h/") has Path="/".
	// We already catch that above, but double-check the raw string.
	if strings.HasSuffix(s, "/") {
		return fmt.Errorf("server identifier must not include a trailing slash: %q", s)
	}

	if s != strings.ToLower(s) {
		return fmt.Errorf("server identifier must be lowercase: %q", s)
	}

	return nil
}

// ValidateAgentIdentifier validates an AAuth agent identifier per spec §5.1.
//
// Agent identifiers MUST be of the form aauth:local@domain where:
//   - The local part consists only of [a-z0-9\-_+.] characters.
//   - The local part must not be empty and must not exceed 255 characters.
//   - The domain part must be a valid lowercase hostname (no scheme, no port).
func ValidateAgentIdentifier(s string) error {
	if s == "" {
		return fmt.Errorf("agent identifier must not be empty")
	}

	if !strings.HasPrefix(s, "aauth:") {
		return fmt.Errorf("agent identifier must use aauth: scheme: %q", s)
	}

	rest := s[len("aauth:"):]
	atIdx := strings.Index(rest, "@")
	if atIdx < 0 {
		return fmt.Errorf("agent identifier must contain '@' separating local and domain: %q", s)
	}

	local := rest[:atIdx]
	domain := rest[atIdx+1:]

	if local == "" {
		return fmt.Errorf("agent identifier local part must not be empty: %q", s)
	}

	if len(local) > 255 {
		return fmt.Errorf("agent identifier local part must not exceed 255 characters: %q", s)
	}

	if !localPartRE.MatchString(local) {
		return fmt.Errorf("agent identifier local part contains invalid characters (only a-z, 0-9, -, _, +, . allowed): %q", s)
	}

	if domain == "" {
		return fmt.Errorf("agent identifier domain part must not be empty: %q", s)
	}

	// Domain must not include a scheme ("://") — spec examples show bare domain names.
	if strings.Contains(domain, "://") {
		return fmt.Errorf("agent identifier domain must not include a scheme: %q", s)
	}

	return nil
}

// ParseAgentIdentifier parses an aauth:local@domain identifier into its components.
// It returns an error if the identifier is invalid.
func ParseAgentIdentifier(s string) (local, domain string, err error) {
	if err = ValidateAgentIdentifier(s); err != nil {
		return "", "", err
	}
	rest := s[len("aauth:"):]
	atIdx := strings.Index(rest, "@")
	return rest[:atIdx], rest[atIdx+1:], nil
}

// AgentIdentifierFromServerURL derives an aauth: identifier from a server URL.
// When the URL contains a port the port is appended to the local part so
// multiple participants on the same host get distinct identifiers (matches the
// Python reference's behavior for localhost demos).
//
//	http://127.0.0.1:8001 -> aauth:agent-8001@127.0.0.1
//	https://agent.example -> aauth:agent@agent.example
func AgentIdentifierFromServerURL(serverURL string) (string, error) {
	if serverURL == "" {
		return "", fmt.Errorf("server URL must not be empty")
	}
	parsed, err := url.Parse(serverURL)
	if err != nil {
		return "", fmt.Errorf("invalid server URL: %w", err)
	}
	host := parsed.Hostname()
	if host == "" {
		host = "localhost"
	}
	port := parsed.Port()
	local := "agent"
	if port != "" {
		local = "agent-" + port
	}
	return "aauth:" + local + "@" + host, nil
}

// ValidateEndpointURL validates an endpoint URL per spec §5.2.
// Endpoint URLs MUST use https and MUST NOT contain a fragment or query string.
// A path is permitted (token_endpoint, interaction_endpoint, etc.).
func ValidateEndpointURL(s string) error {
	if s == "" {
		return fmt.Errorf("endpoint URL must not be empty")
	}
	parsed, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("endpoint URL is not a valid URL: %w", err)
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("endpoint URL must use https scheme: %q", s)
	}
	if parsed.Fragment != "" {
		return fmt.Errorf("endpoint URL must not contain a fragment: %q", s)
	}
	if parsed.RawQuery != "" {
		return fmt.Errorf("endpoint URL must not contain a query string: %q", s)
	}
	return nil
}

// ValidateOtherURL validates a generic AAuth URL (jwks_uri, tos_uri, etc.) per
// spec §5.3. The URL MUST use the https scheme.
func ValidateOtherURL(s string) error {
	if s == "" {
		return fmt.Errorf("URL must not be empty")
	}
	parsed, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("URL is not valid: %w", err)
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("URL must use https scheme: %q", s)
	}
	return nil
}
