// Package identifiers validates AAuth server and agent identifier strings as
// specified in AAuth SPEC §5.1 and §12.9.1.
//
// Server identifiers are HTTPS URLs without port, path, query or fragment
// ([ValidateServerIdentifier]). Agent identifiers use the aauth: URI scheme
// with an RFC-5322-style local@domain form ([ValidateAgentIdentifier],
// [ParseAgentIdentifier]). [AgentIdentifierFromServerURL] derives a
// localhost-friendly agent ID from a server URL for demo and test scenarios.
package identifiers
