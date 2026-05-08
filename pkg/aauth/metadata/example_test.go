package metadata_test

import (
	"fmt"

	"aauth-service/pkg/aauth/metadata"
)

func ExampleBuildResourceMetadata() {
	doc := &metadata.ResourceMetadata{
		Resource:              "https://resource.example.com",
		AuthorizationEndpoint: "https://resource.example.com/resource/token",
		JwksURI:               "https://resource.example.com/.well-known/jwks.json",
		SignatureWindow:       60,
	}
	body, err := metadata.BuildResourceMetadata(doc)
	if err != nil {
		fmt.Println("build error:", err)
		return
	}
	fmt.Println(string(body))
	// Output: {"issuer":"https://resource.example.com","authorization_endpoint":"https://resource.example.com/resource/token","jwks_uri":"https://resource.example.com/.well-known/jwks.json","signature_window":60}
}
