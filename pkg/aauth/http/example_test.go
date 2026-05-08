package http_test

import (
	"fmt"

	aauthhttp "aauth-service/pkg/aauth/http"
)

func ExampleDeferredResponse() {
	resp := aauthhttp.DeferredResponse{
		Status:      aauthhttp.StatusPending,
		Location:    "https://ps.example.com/poll/abc",
		RetryAfter:  2,
		Requirement: "interaction",
		URL:         "https://ps.example.com/i/xyz",
		Code:        "ABC123",
	}
	fmt.Println(resp.Status, resp.Location, resp.RetryAfter, resp.Requirement, resp.URL, resp.Code)
	// Output: pending https://ps.example.com/poll/abc 2 interaction https://ps.example.com/i/xyz ABC123
}
