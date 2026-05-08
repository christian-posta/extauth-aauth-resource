package aauth_test

import (
	"context"
	"fmt"
	"net/http"

	"github.com/lestrrat-go/jwx/v2/jwk"

	"aauth-service/pkg/aauth"
)

// nopJWKSClient is a stub JWKSFetcher used to keep the example self-contained.
type nopJWKSClient struct{}

func (nopJWKSClient) Get(ctx context.Context, uri string) (jwk.Set, error) { return jwk.NewSet(), nil }
func (nopJWKSClient) GetMetadata(ctx context.Context, uri string) (map[string]interface{}, error) {
	return map[string]interface{}{}, nil
}
func (nopJWKSClient) Invalidate(uri string) {}

func ExampleVerify() {
	opts := aauth.VerifyOptions{
		Issuer:                     "https://resource.example.com",
		AllowedSignatureKeySchemes: []string{"jwt", "jwks_uri", "hwk"},
		AllowedJWTTypes:            []string{"aa-agent+jwt", "aa-auth+jwt"},
	}

	headers := http.Header{}
	result := aauth.Verify(
		context.Background(),
		opts,
		http.MethodGet,
		"resource.example.com",
		"/api/things",
		headers,
		nopJWKSClient{},
	)

	fmt.Println(result.Identity.Level)
}
