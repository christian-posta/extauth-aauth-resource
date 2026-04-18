package httpsig

import (
	"crypto"
	"fmt"

	"policy_engine/pkg/httpsig/structfields"
)

type SignInput struct {
	Method    string
	Authority string
	Path      string
	Headers   map[string][]string

	Label      string
	Components []string
	Params     structfields.Params

	PrivateKey crypto.PrivateKey
	Alg        string
}

// Sign creates an HTTP signature and returns the serialized Signature and Signature-Input values.
func Sign(in SignInput) (signature []byte, signatureInput string, err error) {
	label := in.Label
	if label == "" {
		label = "sig"
	}

	resolver := NewResolver(RequestInfo{
		Method:    in.Method,
		Authority: in.Authority,
		Path:      in.Path,
		Headers:   in.Headers,
	})

	base, err := BuildSignatureBase(in.Components, in.Params, resolver)
	if err != nil {
		return nil, "", fmt.Errorf("failed to build signature base: %w", err)
	}

	sig, err := SignMessage(in.PrivateKey, []byte(base), in.Alg)
	if err != nil {
		return nil, "", fmt.Errorf("failed to sign message: %w", err)
	}

	// Build Signature-Input value
	items := make([]structfields.Item, len(in.Components))
	for i, c := range in.Components {
		items[i] = structfields.Item{Value: c}
	}

	innerList := structfields.InnerList{
		Items:  items,
		Params: in.Params,
	}

	dict := structfields.Dictionary{
		{Name: label, Value: innerList},
	}

	sigInputStr, err := structfields.SerializeDictionary(dict)
	if err != nil {
		return nil, "", fmt.Errorf("failed to serialize signature-input: %w", err)
	}

	return sig, sigInputStr, nil
}
