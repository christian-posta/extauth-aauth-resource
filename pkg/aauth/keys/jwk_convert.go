package keys

import (
	"crypto"
	"crypto/ed25519"
	_ "crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

func Ed25519PublicKeyToJWK(pub ed25519.PublicKey, kid string) (jwk.Key, error) {
	k, err := jwk.FromRaw(pub)
	if err != nil {
		return nil, fmt.Errorf("jwk_convert: from raw ed25519: %w", err)
	}
	if kid != "" {
		if err := k.Set(jwk.KeyIDKey, kid); err != nil {
			return nil, fmt.Errorf("jwk_convert: set kid: %w", err)
		}
	}
	return k, nil
}

func JWKToEd25519PublicKey(k jwk.Key) (ed25519.PublicKey, error) {
	var pub ed25519.PublicKey
	if err := k.Raw(&pub); err != nil {
		return nil, fmt.Errorf("jwk_convert: to ed25519 public key: %w", err)
	}
	return pub, nil
}

func Thumbprint(k jwk.Key) (string, error) {
	tp, err := k.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("jwk_convert: thumbprint: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(tp), nil
}
