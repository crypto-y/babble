// Package dh implements the DH functions specified in the noise protocol.
//
// It currently supports three curves:
//  - Curve 448, which uses https://gitlab.com/yawning/x448.git.
//  - Curve 25519, which uses https://golang.org/x/crypto/curve25519.
//  - Curve secp256k1, which uses https://github.com/btcsuite/btcd/btcec.
package dh

import (
	"errors"
	"fmt"
	"strings"
)

// MinDHLEN specifies the minimal size in bytes of public keys and DH
// outputs. For security reasons, it must be 32 or greater.
const MinDHLEN = 32

var (
	// ErrMismatchedPublicKey is returned when the public key fails to match.
	ErrMismatchedPublicKey = errors.New("public key mismatch")

	supportedCurves = map[string]NewCurve{}
)

// NewCurve creates an Curve instance.
type NewCurve func() Curve

// PublicKey represents a public key. The only place to use it is during a DHKE,
// a public key struct is passed into the DH function.
type PublicKey interface {
	// Bytes turns the underlying bytes array into a slice.
	Bytes() []byte

	// Hex returns the hexstring of the public key.
	Hex() string

	// LoadBytes loads the byte slice into a byte array specifically for a
	// public key defined in each curve.
	LoadBytes(data []byte) error
}

// PrivateKey is a key pair. Since a private key always corresponds to at least
// one public key, it makes sense to pair with it inside the struct.
type PrivateKey interface {
	// Bytes turns the underlying bytes array into a slice.
	Bytes() []byte

	// DH performs a Diffie-Hellman calculation between the private key itself
	// and the public key supplied, returns an output sequence of bytes of
	// length DHLEN.
	//
	// Implementations must handle invalid public keys either by returning some
	// output which is purely a function of the public key and does not depend
	// on the private key, or by signaling an error to the caller. The DH
	// function may define more specific rules for handling invalid values.
	DH(pub []byte) ([]byte, error)

	// Update updates both the private key bytes and the public key bytes with
	// the data supplied. This means the calculation of the public key from the
	// private key shall be implemented inside this method.
	Update(data []byte)

	// PubKey returns the associated public key.
	PubKey() PublicKey
}

// Curve represents DH functions specified in the noise specs.
type Curve interface {
	fmt.Stringer

	// GenerateKeyPair generates a new Diffie-Hellman key pair. It creates a key
	// pair from entropy. If the entropy is not supplied, it will use rand.Read
	// to generate a new private key.
	GenerateKeyPair(entropy []byte) (PrivateKey, error)

	// Size returns the DHLEN value.
	Size() int
}

// FromString uses the provided curve name, s, to query a built-in curve.
func FromString(s string) (Curve, error) {
	if supportedCurves[s] != nil {
		return supportedCurves[s](), nil
	}
	return nil, errUnsupported(s)
}

// Register updates the supported curves used in package dh.
func Register(s string, new NewCurve) {
	// TODO: check registry

	// check the AEAD interface is matched
	var _ Curve = new()

	supportedCurves[s] = new
}

// SupportedCurves gives the names of all the curves registered. If no new
// curves are registered, it returns a string as "25519, 448, secp256k1", orders
// not preserved.
func SupportedCurves() string {
	keys := make([]string, 0, len(supportedCurves))
	for k := range supportedCurves {
		keys = append(keys, k)
	}
	return strings.Join(keys, ", ")
}

func errUnsupported(s string) error {
	return fmt.Errorf("curve: %s is unsupported", s)
}
