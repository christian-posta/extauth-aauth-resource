// Package metadata provides Go types for AAuth well-known metadata documents
// and a [Fetcher] that retrieves them.
//
// The four document types correspond to AAuth SPEC §12.10:
//
//   - [ResourceMetadata]      — /.well-known/aauth-resource.json (§12.10.2)
//   - [AgentServerMetadata]   — /.well-known/aauth-agent.json
//   - [AuthServerMetadata]    — /.well-known/aauth-access.json
//   - [PersonServerMetadata]  — /.well-known/aauth-person.json
//
// The Build* helpers ([BuildResourceMetadata] etc.) marshal these structs to
// JSON. [Fetcher] resolves a server identifier to the matching well-known URL
// (using [aauth-service/pkg/aauth/identifiers] for validation) and unmarshals
// the response.
package metadata
