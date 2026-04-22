// sign-request generates a curl command with a valid AAuth HTTP Message Signature.
//
// Usage:
//
//	go run ./cmd/sign-request \
//	  -method POST \
//	  -authority localhost:3000 \
//	  -path /gemini/v1/chat/completions \
//	  -body '{"model":"gemini-2.5-flash-lite","messages":[{"role":"user","content":"hello"}]}'
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"strings"
	"time"

	"aauth-service/pkg/httpsig"
	"aauth-service/pkg/httpsig/structfields"
)

func main() {
	method    := flag.String("method", "GET", "HTTP method")
	authority := flag.String("authority", "localhost:3000", "Host:port")
	path      := flag.String("path", "/", "URL path")
	body      := flag.String("body", "", "Request body (for POST)")
	flag.Parse()

	// Generate a fresh ephemeral Ed25519 key (hwk scheme — pseudonymous).
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	x64 := base64.RawURLEncoding.EncodeToString(pub)
	sigKeyVal := `sig=hwk;kty="OKP";crv="Ed25519";x="` + x64 + `"`

	headers := map[string][]string{
		"signature-key": {sigKeyVal},
	}

	params := structfields.Params{
		{Name: "created", Value: time.Now().Unix()},
		{Name: "alg", Value: "ed25519"},
	}

	signInput := httpsig.SignInput{
		Method:     strings.ToUpper(*method),
		Authority:  *authority,
		Path:       *path,
		Headers:    headers,
		Label:      "sig",
		Components: []string{"@method", "@authority", "@path", "signature-key"},
		Params:     params,
		PrivateKey: priv,
		Alg:        "ed25519",
	}

	sigBytes, sigInputStr, err := httpsig.Sign(signInput)
	if err != nil {
		panic(err)
	}

	sigHdr := `sig=:` + base64.StdEncoding.EncodeToString(sigBytes) + `:`

	bodyFlag := ""
	if *body != "" {
		escaped := strings.ReplaceAll(*body, `'`, `'"'"'`)
		bodyFlag = fmt.Sprintf(" -d '%s'", escaped)
	}

	fmt.Printf("curl -si -X %s 'http://%s%s' \\\n", strings.ToUpper(*method), *authority, *path)
	fmt.Printf("  -H 'Content-Type: application/json' \\\n")
	fmt.Printf("  -H 'signature-key: %s' \\\n", sigKeyVal)
	fmt.Printf("  -H 'signature-input: %s' \\\n", sigInputStr)
	fmt.Printf("  -H 'signature: %s'", sigHdr)
	if bodyFlag != "" {
		fmt.Printf(" \\%s\n", bodyFlag)
	} else {
		fmt.Println()
	}
}
