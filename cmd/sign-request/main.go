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
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/christian-posta/aauth-go-library/pkg/aauth/agent"
)

func main() {
	method    := flag.String("method", "GET", "HTTP method")
	authority := flag.String("authority", "localhost:3000", "Host:port")
	path      := flag.String("path", "/", "URL path")
	body      := flag.String("body", "", "Request body (for POST)")
	flag.Parse()

	// Generate a fresh ephemeral Ed25519 key (hwk scheme — pseudonymous).
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	signer, err := agent.NewRequestSigner(agent.SignerOptions{
		AgentID:   "aauth:cli@local",
		KeyID:     "sig",
		Signer:    priv,
		Algorithm: "ed25519",
	})
	if err != nil {
		panic(err)
	}

	rawURL := "http://" + *authority + *path
	req, err := http.NewRequest(strings.ToUpper(*method), rawURL, nil)
	if err != nil {
		panic(err)
	}

	comps := []string{"@method", "@authority", "@path", "signature-key"}
	if err := signer.Sign(req.Context(), req, comps); err != nil {
		panic(err)
	}

	sigKeyVal := req.Header.Get("signature-key")
	sigInputVal := req.Header.Get("signature-input")
	sigVal := req.Header.Get("signature")

	targetURL := &url.URL{Scheme: "http", Host: *authority, Path: *path}

	bodyFlag := ""
	if *body != "" {
		escaped := strings.ReplaceAll(*body, `'`, `'"'"'`)
		bodyFlag = fmt.Sprintf(" -d '%s'", escaped)
	}

	fmt.Printf("curl -si -X %s '%s' \\\n", strings.ToUpper(*method), targetURL.String())
	fmt.Printf("  -H 'Content-Type: application/json' \\\n")
	fmt.Printf("  -H 'signature-key: %s' \\\n", sigKeyVal)
	fmt.Printf("  -H 'signature-input: %s' \\\n", sigInputVal)
	fmt.Printf("  -H 'signature: %s'", sigVal)
	if bodyFlag != "" {
		fmt.Printf(" \\%s\n", bodyFlag)
	} else {
		fmt.Println()
	}
}
