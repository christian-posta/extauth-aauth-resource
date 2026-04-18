package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"time"

	"policy_engine/pkg/httpsig"
	"policy_engine/pkg/httpsig/structfields"
)

func main() {
	// Generate client key
	pub, priv, _ := ed25519.GenerateKey(nil)

	// Create Signature-Key
	pubBytes := pub
	x64 := base64.RawURLEncoding.EncodeToString(pubBytes)
	sigKeyVal := `sig=?1;scheme="hwk";kty="OKP";crv="Ed25519";x="` + x64 + `"`

	headers := map[string][]string{
		"signature-key": {sigKeyVal},
	}

	now := time.Now().Unix()
	params := structfields.Params{
		{Name: "created", Value: now},
		{Name: "alg", Value: "ed25519"},
	}

	signInput := httpsig.SignInput{
		Method:     "GET",
		Authority:  "localhost",
		Path:       "/",
		Headers:    headers,
		Label:      "sig",
		Components: []string{"@method", "@authority", "@path", "signature-key"},
		Params:     params,
		PrivateKey: priv,
		Alg:        "ed25519",
	}

	sigBytes, sigInputStr, _ := httpsig.Sign(signInput)

	fmt.Printf("curl -i http://localhost:3001/ -H 'Host: localhost' -H 'signature-key: %s' -H 'signature-input: %s' -H 'signature: sig=:%s:'\n", sigKeyVal, sigInputStr, base64.StdEncoding.EncodeToString(sigBytes))
}
