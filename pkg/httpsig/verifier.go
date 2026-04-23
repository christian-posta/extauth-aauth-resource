package httpsig

import (
	"crypto"
	"errors"
	"fmt"
	"log"
	"time"

	"aauth-service/pkg/httpsig/structfields"
)

var (
	ErrMissingSignature            = errors.New("missing signature headers")
	ErrExpiredSignature            = errors.New("expired signature")
	ErrFutureSignature             = errors.New("future signature")
	ErrMissingSignatureKeyCoverage = errors.New("missing signature-key coverage")
	ErrMissingCoverage             = errors.New("missing required component coverage")
	ErrInvalidInput                = errors.New("invalid signature input")
)

type VerifyInput struct {
	Method    string
	Authority string
	Path      string
	Headers   map[string][]string

	Label              string
	RequiredComponents []string
	AllowedAlgs        []string
	MaxClockSkew       time.Duration

	PublicKey crypto.PublicKey
	Alg       string
}

type VerifyResult struct {
	Label   string
	Created time.Time
	Covered []string
	KeyID   string
}

func Verify(in VerifyInput) (*VerifyResult, error) {
	if len(in.Headers["signature-input"]) == 0 || len(in.Headers["signature"]) == 0 {
		return nil, ErrMissingSignature
	}

	// 1. Parse Signature-Input
	// It can be spread across multiple headers. RFC 8941 section 4.2 allows combining with commas.
	var sigInputStr string
	for i, v := range in.Headers["signature-input"] {
		if i > 0 {
			sigInputStr += ", "
		}
		sigInputStr += v
	}

	sigInputDict, err := structfields.ParseDictionary(sigInputStr)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse signature-input: %v", ErrInvalidInput, err)
	}

	// 2. Select the signature parameters
	label := in.Label
	if label == "" {
		if len(sigInputDict) == 1 {
			label = sigInputDict[0].Name
		} else {
			return nil, fmt.Errorf("%w: multiple signatures present but no label specified", ErrInvalidInput)
		}
	}

	entry, ok := sigInputDict.Get(label)
	if !ok {
		return nil, fmt.Errorf("%w: signature label %q not found", ErrInvalidInput, label)
	}

	innerList, ok := entry.(structfields.InnerList)
	if !ok {
		return nil, fmt.Errorf("%w: signature-input entry is not an inner list", ErrInvalidInput)
	}

	// 3. Extract components and params
	var covered []string
	for _, item := range innerList.Items {
		compStr, ok := item.Value.(string)
		if !ok {
			return nil, fmt.Errorf("%w: covered component is not a string", ErrInvalidInput)
		}
		covered = append(covered, compStr)
	}

	// 4. Enforce required coverage
	coveredMap := make(map[string]bool)
	for _, c := range covered {
		coveredMap[c] = true
	}

	hasSigKey := coveredMap["signature-key"]

	for _, req := range in.RequiredComponents {
		if !coveredMap[req] {
			if req == "signature-key" {
				return nil, ErrMissingSignatureKeyCoverage
			}
			return nil, fmt.Errorf("%w: missing %q", ErrMissingCoverage, req)
		}
	}

	// AAuth explicitly demands signature-key coverage even if the caller forgot to ask
	if !hasSigKey && contains(in.RequiredComponents, "signature-key") {
		return nil, ErrMissingSignatureKeyCoverage
	}

	// 5. Clock skew checks
	var createdTime time.Time
	if createdParam, ok := innerList.Params.Get("created"); ok {
		createdInt, ok := getInt64(createdParam)
		if !ok {
			return nil, fmt.Errorf("%w: invalid 'created' param type", ErrInvalidInput)
		}
		createdTime = time.Unix(createdInt, 0)

		now := time.Now()
		if now.Sub(createdTime) > in.MaxClockSkew {
			return nil, ErrExpiredSignature
		}
		if createdTime.Sub(now) > in.MaxClockSkew {
			return nil, ErrFutureSignature
		}
	}

	// 6. Check 'alg'
	alg := in.Alg
	if algParam, ok := innerList.Params.Get("alg"); ok {
		algStr, ok := algParam.(string)
		if !ok {
			return nil, fmt.Errorf("%w: invalid 'alg' param type", ErrInvalidInput)
		}

		allowed := false
		for _, a := range in.AllowedAlgs {
			if a == algStr {
				allowed = true
				break
			}
		}
		if len(in.AllowedAlgs) > 0 && !allowed {
			return nil, fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, algStr)
		}

		if alg != "" && algStr != alg {
			return nil, fmt.Errorf("%w: alg mismatch: %q vs %q", ErrInvalidSignature, algStr, alg)
		}
		alg = algStr
	}

	// 7. Parse Signature header
	var sigStr string
	for i, v := range in.Headers["signature"] {
		if i > 0 {
			sigStr += ", "
		}
		sigStr += v
	}

	sigDict, err := structfields.ParseDictionary(sigStr)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse signature header: %v", ErrInvalidInput, err)
	}

	sigEntry, ok := sigDict.Get(label)
	if !ok {
		return nil, fmt.Errorf("%w: signature for label %q not found", ErrInvalidInput, label)
	}

	sigItem, ok := sigEntry.(structfields.Item)
	if !ok {
		return nil, fmt.Errorf("%w: signature entry is not an item", ErrInvalidInput)
	}

	sigBytes, ok := sigItem.Value.([]byte)
	if !ok {
		return nil, fmt.Errorf("%w: signature is not a byte sequence", ErrInvalidInput)
	}

	// 8. Build base
	resolver := NewResolver(RequestInfo{
		Method:    in.Method,
		Authority: in.Authority,
		Path:      in.Path,
		Headers:   in.Headers,
	})

	base, err := BuildSignatureBase(covered, innerList.Params, resolver)
	if err != nil {
		log.Printf("[aauth-debug] httpsig BuildSignatureBase failed method=%q authority=%q path=%q err=%v",
			in.Method, in.Authority, in.Path, err)
		return nil, fmt.Errorf("failed to build signature base: %w", err)
	}

	// 9. Verify
	if err := VerifySignature(in.PublicKey, []byte(base), sigBytes, alg); err != nil {
		log.Printf("[aauth-debug] httpsig VerifySignature failed method=%q authority=%q path=%q alg=%q err=%v\nsignature_base:\n%s",
			in.Method, in.Authority, in.Path, alg, err, base)
		return nil, err
	}

	keyID := ""
	if kidParam, ok := innerList.Params.Get("keyid"); ok {
		if kidStr, ok := kidParam.(string); ok {
			keyID = kidStr
		}
	}

	return &VerifyResult{
		Label:   label,
		Created: createdTime,
		Covered: covered,
		KeyID:   keyID,
	}, nil
}

func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

func getInt64(v interface{}) (int64, bool) {
	switch val := v.(type) {
	case int:
		return int64(val), true
	case int64:
		return val, true
	case float64:
		return int64(val), true
	}
	return 0, false
}
