package extauthz

import (
	"log"
	"net"
	"sort"
	"strings"

	pb "aauth-service/gen/proto"
)

// authorityResolution describes how we derived authority (for failure logging).
type authorityResolution struct {
	mergeBranch          string
	getHost              string
	hostHeader           string
	authorityHeader      string
	mergedBeforeOverride string
}

func describeAuthorityResolution(httpReq *pb.AttributeContext_HttpRequest) authorityResolution {
	var r authorityResolution
	if httpReq == nil {
		r.mergeBranch = "nil_httpReq"
		return r
	}
	r.getHost = strings.TrimSpace(httpReq.GetHost())
	hdr := httpReq.GetHeaders()
	r.hostHeader = headerValueCI(hdr, "host")
	r.authorityHeader = headerValueCI(hdr, ":authority")
	r.mergedBeforeOverride = AuthorityForSignature(httpReq)
	switch {
	case len(hdr) == 0:
		r.mergeBranch = "no_headers_map"
	case r.hostHeader != "":
		r.mergeBranch = "merge_Host_header"
	case r.authorityHeader != "":
		r.mergeBranch = "merge_:authority_header"
	default:
		r.mergeBranch = "fallback_GetHost_only"
	}
	return r
}

// LogAuthorityResolutionOnFailure logs how @authority was chosen (only call on verification errors).
func LogAuthorityResolutionOnFailure(httpReq *pb.AttributeContext_HttpRequest, finalAuthority string, overrideSet bool, resourceID string) {
	d := describeAuthorityResolution(httpReq)
	log.Printf("[aauth-debug] resource=%s authority_resolution branch=%q GetHost=%q Host_header=%q :authority_header=%q merged_before_override=%q authority_override_set=%v final_authority_used=%q",
		resourceID, d.mergeBranch, d.getHost, d.hostHeader, d.authorityHeader, d.mergedBeforeOverride, overrideSet, finalAuthority)
	if httpReq == nil {
		return
	}
	hdr := httpReq.GetHeaders()
	if len(hdr) == 0 {
		return
	}
	keys := make([]string, 0, len(hdr))
	for k := range hdr {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		log.Printf("[aauth-debug] resource=%s raw_headers[%q]=%q", resourceID, k, hdr[k])
	}
}

// AuthorityForSignature returns the HTTP authority string used for RFC 9421
// @authority and related checks.
//
// It merges AttributeContext.HttpRequest.host (GetHost) with the Host header
// when present, otherwise with :authority (typical HTTP/2). If the field and
// header disagree, the value that carries an explicit non-default port (not 80
// or 443) is preferred so @authority matches what clients sign.
func AuthorityForSignature(httpReq *pb.AttributeContext_HttpRequest) string {
	if httpReq == nil {
		return ""
	}
	g := strings.TrimSpace(httpReq.GetHost())
	headers := httpReq.GetHeaders()
	if len(headers) == 0 {
		return g
	}
	if h := headerValueCI(headers, "host"); h != "" {
		return mergeGetHostAndHeader(g, h)
	}
	if a := headerValueCI(headers, ":authority"); a != "" {
		return mergeGetHostAndHeader(g, a)
	}
	return g
}

// mergeGetHostAndHeader combines the ext_authz host field with Host or
// :authority from headers per the rules described on AuthorityForSignature.
func mergeGetHostAndHeader(getHost, headerAuth string) string {
	g := strings.TrimSpace(getHost)
	ha := strings.TrimSpace(headerAuth)
	if ha == "" {
		return g
	}
	if g == "" {
		return ha
	}
	if g == ha {
		return g
	}
	gNonStd := hasExplicitNonStandardPort(g)
	hNonStd := hasExplicitNonStandardPort(ha)
	if gNonStd != hNonStd {
		if gNonStd {
			return g
		}
		return ha
	}
	return ha
}

// hasExplicitNonStandardPort reports whether authority includes an explicit
// port other than 80 or 443 (the common defaults).
func hasExplicitNonStandardPort(authority string) bool {
	authority = strings.TrimSpace(authority)
	if authority == "" {
		return false
	}
	_, port, err := net.SplitHostPort(authority)
	if err != nil {
		return false
	}
	switch port {
	case "80", "443":
		return false
	default:
		return true
	}
}

func headerValueCI(headers map[string]string, name string) string {
	want := strings.ToLower(name)
	for k, v := range headers {
		if strings.ToLower(k) != want {
			continue
		}
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}
