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
)

// MinDHLEN specifies the minimal size in bytes of public keys and DH
// outputs. For security reasons, it must be 32 or greater.
const MinDHLEN = 32

var (
	// ErrMismatchedPublicKey is returned when the public key fails to match.
	ErrMismatchedPublicKey = errors.New("public key mismatch")

	supportedCurves = map[string]Curve{
		// "25519":     X25519,
		// "448":       X448,
		// "secp256k1": Secp256k1,
	}
)

// PublicKey represents a public key. The only place to use it is during a DHKE,
// a public key struct is passed into the DH function.
type PublicKey interface {
	// Bytes turns the underlying bytes array into a slice.
	Bytes() []byte

	// Hex returns the hexstring of the public key.
	Hex() string
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
	DH(pub PublicKey) ([]byte, error)

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

	// GenerateKeyPair generates a new Diffie-Hellman key pair. A PublicKey
	// represents an encoding of a DH public key into a byte sequence of length
	// DHLEN. The publicKey encoding details are specific to each set of DH
	// functions.
	GenerateKeyPair(entropy []byte) (PrivateKey, error)

	// Size returns the DHLEN value.
	Size() int
}

// FromString uses the provided curve name, s, to query a built-in curve.
func FromString(s string) Curve {
	return supportedCurves[s]
}

// Register updates the supported curves used in package dh.
func Register(s string, c Curve) {
	// TODO: check registry
	supportedCurves[s] = c
}
