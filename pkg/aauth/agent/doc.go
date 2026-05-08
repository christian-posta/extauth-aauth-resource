// Package agent provides the agent-side AAuth SDK: signing outgoing requests,
// exchanging resource tokens for auth tokens, and handling deferred (202) flows.
//
// The high-level entry point is [ExchangeResourceToken], which orchestrates
// [TokenExchanger] and [Poller] to perform the full three-party exchange
// described in AAuth SPEC §7.6 (resource-token to auth-token). [RequestSigner]
// produces the Signature, Signature-Input and Signature-Key headers required
// by SPEC §6 and draft-hardt-httpbis-signature-key.
//
// A [ChallengeHandler] interprets 401 responses (AAuth-Requirement,
// Accept-Signature) and returns an [Action] telling callers how to retry.
package agent
