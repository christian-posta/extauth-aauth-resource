// Package transport provides an http.RoundTripper that signs every outbound
// request with an AAuth [agent.RequestSigner].
//
// Wrap any base transport with [NewSigningTransport] to give a stock
// *http.Client transparent agent-signing behaviour: the wrapper attaches
// Signature, Signature-Input and Signature-Key headers per AAuth SPEC §6
// before forwarding the request. The list of covered components is
// configurable so callers can pin additional fields (e.g. the resource's
// AdditionalSignatureComponents).
package transport
