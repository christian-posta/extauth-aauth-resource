package headers_test

import (
	"fmt"

	"aauth-service/pkg/aauth/headers"
)

func ExampleBuildAAuthRequirement_authToken() {
	out, err := headers.BuildAAuthRequirement([]headers.Requirement{
		headers.AuthTokenReq{
			Issuer:        "https://resource.example.com",
			Audience:      "https://ps.example.com",
			ResourceToken: "eyJhbGciOiJFZERTQSJ9.payload.sig",
		},
	})
	if err != nil {
		fmt.Println("build error:", err)
		return
	}
	fmt.Println(out)
	// Output: requirement=auth-token, resource-token="eyJhbGciOiJFZERTQSJ9.payload.sig"
}

func ExampleBuildAAuthRequirement_interaction() {
	out, err := headers.BuildAAuthRequirement([]headers.Requirement{
		headers.InteractionReq{
			URL:  "https://ps.example.com/i/abc",
			Code: "XYZ789",
		},
	})
	if err != nil {
		fmt.Println("build error:", err)
		return
	}
	fmt.Println(out)
	// Output: requirement=interaction, url="https://ps.example.com/i/abc", code="XYZ789"
}
