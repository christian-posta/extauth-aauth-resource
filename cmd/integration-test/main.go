// integration-test: calls the live AAuth gRPC service directly, bypassing agentgateway,
// to test the full flow and identify what authority agentgateway actually sends.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "aauth-service/gen/proto"
	"aauth-service/pkg/httpsig"
	"aauth-service/pkg/httpsig/structfields"
)

func main() {
	conn, err := grpc.Dial("localhost:7070", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	client := pb.NewAuthorizationClient(conn)

	// Generate a fresh key
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	x64 := base64.RawURLEncoding.EncodeToString(pub)
	sigKeyVal := `sig=hwk;kty="OKP";crv="Ed25519";x="` + x64 + `"`

	// Authorities to try — to figure out what agentgateway actually sends
	authorities := []string{
		"localhost:3001",
		"localhost",
	}

	for _, authority := range authorities {
		fmt.Printf("\n═══ Testing @authority=%q ═══\n", authority)

		headers := map[string][]string{
			"signature-key": {sigKeyVal},
		}

		params := structfields.Params{
			{Name: "created", Value: time.Now().Unix()},
			{Name: "alg", Value: "ed25519"},
		}

		sigIn := httpsig.SignInput{
			Method:     "GET",
			Authority:  authority,
			Path:       "/",
			Headers:    headers,
			Label:      "sig",
			Components: []string{"@method", "@authority", "@path", "signature-key"},
			Params:     params,
			PrivateKey: priv,
			Alg:        "ed25519",
		}

		sigBytes, sigInputStr, err := httpsig.Sign(sigIn)
		if err != nil {
			log.Printf("sign error: %v", err)
			continue
		}

		req := &pb.CheckRequest{
			Attributes: &pb.AttributeContext{
				ContextExtensions: map[string]string{
					"aauth_resource_id": "mcp-api",
				},
				Request: &pb.AttributeContext_Request{
					Http: &pb.AttributeContext_HttpRequest{
						Method: "GET",
						Host:   authority,
						Path:   "/",
						Headers: map[string]string{
							"signature-key":   sigKeyVal,
							"signature-input": sigInputStr,
							"signature":       "sig=:" + base64.StdEncoding.EncodeToString(sigBytes) + ":",
						},
					},
				},
			},
		}

		resp, err := client.Check(context.Background(), req)
		if err != nil {
			log.Printf("rpc error: %v", err)
			continue
		}

		code := resp.GetStatus().GetCode()
		switch r := resp.HttpResponse.(type) {
		case *pb.CheckResponse_OkResponse:
			fmt.Printf("  ✓ ALLOWED (code=%d), headers:\n", code)
			for _, h := range r.OkResponse.GetHeaders() {
				fmt.Printf("    %s: %s\n", h.Header.Key, h.Header.Value)
			}
		case *pb.CheckResponse_DeniedResponse:
			fmt.Printf("  ✗ DENIED (code=%d), body: %s\n", code, r.DeniedResponse.Body)
			for _, h := range r.DeniedResponse.GetHeaders() {
				fmt.Printf("    %s: %s\n", h.Header.Key, h.Header.Value)
			}
		}
	}
}
