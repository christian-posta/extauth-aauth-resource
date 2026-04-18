package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
)

func main() {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	b, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		panic(err)
	}

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: b,
	}

	out, err := os.Create("resource_key.pem")
	if err != nil {
		panic(err)
	}
	defer out.Close()
	pem.Encode(out, block)

	// Save pub key to a separate file
	pubBytes, _ := x509.MarshalPKIXPublicKey(pub)
	pubBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}
	outPub, _ := os.Create("resource_pub.pem")
	defer outPub.Close()
	pem.Encode(outPub, pubBlock)
}
