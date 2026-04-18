package httpsig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
)

var (
	ErrUnsupportedAlgorithm = errors.New("unsupported signature algorithm")
	ErrInvalidSignature     = errors.New("invalid signature")
	ErrInvalidKey           = errors.New("invalid key for algorithm")
)

// VerifySignature verifies a signature using the specified algorithm and public key.
func VerifySignature(pub crypto.PublicKey, msg, sig []byte, alg string) error {
	switch alg {
	case "ed25519":
		edPub, ok := pub.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("%w: expected ed25519.PublicKey", ErrInvalidKey)
		}
		if !ed25519.Verify(edPub, msg, sig) {
			return ErrInvalidSignature
		}
		return nil

	case "ecdsa-p256":
		ecPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: expected *ecdsa.PublicKey", ErrInvalidKey)
		}

		// ECDSA signatures in HTTPSig are IEEE P1363 (R || S) format, 64 bytes for P-256
		if len(sig) != 64 {
			return fmt.Errorf("%w: ecdsa-p256 signature must be 64 bytes", ErrInvalidSignature)
		}

		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])

		hash := sha256.Sum256(msg)
		if !ecdsa.Verify(ecPub, hash[:], r, s) {
			return ErrInvalidSignature
		}
		return nil

	default:
		return fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, alg)
	}
}

// SignMessage signs a message using the specified private key.
func SignMessage(priv crypto.PrivateKey, msg []byte, alg string) ([]byte, error) {
	switch alg {
	case "ed25519":
		edPriv, ok := priv.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: expected ed25519.PrivateKey", ErrInvalidKey)
		}
		return ed25519.Sign(edPriv, msg), nil

	case "ecdsa-p256":
		ecPriv, ok := priv.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: expected *ecdsa.PrivateKey", ErrInvalidKey)
		}

		hash := sha256.Sum256(msg)
		// Note: for strict AAuth, should use RFC 6979 deterministic ECDSA.
		// Go's ecdsa.Sign uses a mixed approach that is safe.
		r, s, err := ecdsa.Sign(rand.Reader, ecPriv, hash[:])
		if err != nil {
			return nil, err
		}

		// Encode as IEEE P1363
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		return sig, nil

	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, alg)
	}
}
