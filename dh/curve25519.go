package dh

import (
	"crypto/rand"
	"encoding/hex"

	"golang.org/x/crypto/curve25519"
)

// DHLEN25519 defines the DHLEN for x25519.
const DHLEN25519 = 32

// X25519 implements the DH interface for Curve25519.
var X25519 Curve = &Curve25519{DHLEN: DHLEN25519}

// PublicKey25519 implements the PublicKey interface.
type PublicKey25519 struct {
	raw [DHLEN25519]byte
}

// Bytes turns the underlying bytes array into a slice.
func (pk *PublicKey25519) Bytes() []byte {
	return pk.raw[:]
}

// Hex returns the public key in hexstring.
func (pk *PublicKey25519) Hex() string {
	return hex.EncodeToString(pk.Bytes())
}

// PrivateKey25519 implements the PrivateKey interface.
type PrivateKey25519 struct {
	raw [DHLEN25519]byte
	pub *PublicKey25519
}

// Bytes turns the underlying byte array into a slice.
func (pk *PrivateKey25519) Bytes() []byte {
	return pk.raw[:]
}

// DH performs a Diffie-Hellman calculation between the private key itself and
// the public key.
func (pk *PrivateKey25519) DH(pub PublicKey) ([]byte, error) {
	// replace the interface's value for public key
	pubKey, ok := pub.(*PublicKey25519)
	if !ok {
		return nil, ErrMismatchedPublicKey
	}

	var shared [DHLEN25519]byte
	curve25519.ScalarMult(&shared, &pk.raw, &pubKey.raw)
	return shared[:], nil
}

// Update writes secret to the private key.
func (pk *PrivateKey25519) Update(data []byte) {
	copy(pk.raw[:], data[:DHLEN25519])

	// calcuate the public key
	curve25519.ScalarBaseMult(&pk.pub.raw, &pk.raw)
}

// PubKey returns the corresponding public key.
func (pk *PrivateKey25519) PubKey() PublicKey {
	return pk.pub
}

// Curve25519 implements the DH interface(aka "X25519").
type Curve25519 struct {
	DHLEN int
}

// GenerateKeyPair creates a key pair from entropy. If the entropy is not
// supplied, it will use rand.Read to generate a new private key.
func (dh *Curve25519) GenerateKeyPair(entropy []byte) (PrivateKey, error) {
	secret := make([]byte, DHLEN25519)

	if entropy != nil {
		// entropy is given, use it to create the private key.
		copy(secret, entropy[:DHLEN25519])
	} else {
		// no entropy given, use the default rand.Read.
		if _, err := rand.Read(secret); err != nil {
			return nil, err
		}
	}

	// set the raw data for both private and public keys.
	priv := &PrivateKey25519{pub: &PublicKey25519{}}
	priv.Update(secret)
	return priv, nil
}

// Size returns the DHLEN.
func (dh *Curve25519) Size() int {
	return dh.DHLEN
}

func (dh *Curve25519) String() string {
	return "25519"
}

func init() {
	Register(X25519.String(), X25519)
}
