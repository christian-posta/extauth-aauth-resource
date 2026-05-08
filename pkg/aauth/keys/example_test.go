package keys_test

import (
	"net/http"
	"time"

	"aauth-service/pkg/aauth/keys"
)

func ExampleNewJWKSFetcher() {
	fetcher := keys.NewJWKSFetcher(keys.FetcherOptions{
		HTTPClient: http.DefaultClient,
		DefaultTTL: 5 * time.Minute,
		MaxAge:     24 * time.Hour,
		MinRefetch: 60 * time.Second,
	})
	_ = fetcher
}
