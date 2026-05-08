// Package http defines helpers for AAuth's deferred (202 Accepted) response
// flow described in AAuth SPEC §7.7.
//
// [DeferredResponse] models the JSON body returned alongside a 202 status when
// authorization cannot complete synchronously — typically because a human must
// interact (interaction requirement) or a clarifying answer is needed. The
// status constants [StatusPending], [StatusInteracting] and [StatusCompleted]
// match the values emitted by Person Servers.
package http
