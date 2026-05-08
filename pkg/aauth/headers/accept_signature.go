package headers

import (
	"fmt"
	"strings"

	"aauth-service/pkg/httpsig/structfields"
)

// AcceptSignature represents the parsed value of an Accept-Signature header
// per draft-hardt-httpbis-signature-key.
//
// The header declares that the resource accepts (and may require) HTTP Message
// Signatures.  Key discovery type is indicated by the sigkey parameter on each
// inner list in the RFC 8941 Dictionary.
type AcceptSignature struct {
	// Components is the list of covered component identifiers (e.g. "@method", "@path").
	Components []string
	// KeyTypes lists the sigkey parameter values found across all entries
	// (e.g. "jkt" for pseudonym, "uri" for identity).
	KeyTypes []string
	// Algorithms lists any alg parameter values found across all entries.
	Algorithms []string
}

// ParseAcceptSignature parses an Accept-Signature header value.
func ParseAcceptSignature(headerValue string) (*AcceptSignature, error) {
	if strings.TrimSpace(headerValue) == "" {
		return nil, fmt.Errorf("Accept-Signature: empty header value")
	}

	dict, err := structfields.ParseDictionary(headerValue)
	if err != nil {
		return nil, fmt.Errorf("Accept-Signature: invalid structured field: %w", err)
	}

	as := &AcceptSignature{}
	compsSeen := map[string]bool{}
	ktSeen := map[string]bool{}
	algSeen := map[string]bool{}

	for _, member := range dict {
		il, ok := member.Value.(structfields.InnerList)
		if !ok {
			continue
		}

		for _, it := range il.Items {
			var comp string
			switch v := it.Value.(type) {
			case string:
				comp = v
			case structfields.Token:
				comp = string(v)
			}
			if comp != "" && !compsSeen[comp] {
				as.Components = append(as.Components, comp)
				compsSeen[comp] = true
			}
		}

		if v, ok := il.Params.Get("sigkey"); ok {
			var kt string
			switch s := v.(type) {
			case structfields.Token:
				kt = string(s)
			case string:
				kt = s
			}
			if kt != "" && !ktSeen[kt] {
				as.KeyTypes = append(as.KeyTypes, kt)
				ktSeen[kt] = true
			}
		}

		if v, ok := il.Params.Get("alg"); ok {
			var alg string
			switch s := v.(type) {
			case string:
				alg = s
			case structfields.Token:
				alg = string(s)
			}
			if alg != "" && !algSeen[alg] {
				as.Algorithms = append(as.Algorithms, alg)
				algSeen[alg] = true
			}
		}
	}

	return as, nil
}

// BuildAcceptSignature serializes an AcceptSignature into an RFC 8941 Dictionary
// header value.
//
// When KeyTypes has more than one entry, a separate dictionary member (sig1, sig2, …)
// is emitted for each key type, all sharing the same Components list.
// When KeyTypes is empty, a single "sig" entry without a sigkey parameter is emitted.
func BuildAcceptSignature(as *AcceptSignature) (string, error) {
	if as == nil {
		return "", fmt.Errorf("BuildAcceptSignature: nil AcceptSignature")
	}

	items := make([]structfields.Item, len(as.Components))
	for i, comp := range as.Components {
		items[i] = structfields.Item{Value: comp}
	}

	dict := structfields.Dictionary{}

	if len(as.KeyTypes) == 0 {
		dict = append(dict, structfields.DictMember{
			Name:  "sig",
			Value: structfields.InnerList{Items: items},
		})
	} else {
		for i, kt := range as.KeyTypes {
			name := fmt.Sprintf("sig%d", i+1)
			params := structfields.Params{
				{Name: "sigkey", Value: structfields.Token(kt)},
			}
			if len(as.Algorithms) > 0 {
				params = append(structfields.Params{
					{Name: "alg", Value: as.Algorithms[0]},
				}, params...)
			}
			dict = append(dict, structfields.DictMember{
				Name: name,
				Value: structfields.InnerList{
					Items:  items,
					Params: params,
				},
			})
		}
	}

	return structfields.SerializeDictionary(dict)
}
