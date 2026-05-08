package identifiers_test

import (
	"fmt"

	"aauth-service/pkg/aauth/identifiers"
)

func ExampleValidateServerIdentifier() {
	if err := identifiers.ValidateServerIdentifier("https://issuer.example.com"); err != nil {
		fmt.Println("invalid:", err)
		return
	}
	fmt.Println("valid")
	// Output: valid
}

func ExampleParseAgentIdentifier() {
	local, domain, err := identifiers.ParseAgentIdentifier("aauth:demo-agent@agents.example.com")
	if err != nil {
		fmt.Println("parse error:", err)
		return
	}
	fmt.Printf("local=%s domain=%s\n", local, domain)
	// Output: local=demo-agent domain=agents.example.com
}
