package dh

import (
	"crypto/rand"
	"encoding/hex"

	curve448 "gitlab.com/yawning/x448.git"
)

// DHLEN448 defines the DHLEN for x448.
const DHLEN448 = 56

// X448 implements the DH interface for Curve448.
var X448 Curve = &Curve448{DHLEN: DHLEN448}

// PublicKey448 implements the PublicKey interface.
type PublicKey448 struct {
	raw [DHLEN448]byte
}

// Bytes turns the underlying bytes array into a slice.
func (pk *PublicKey448) Bytes() []byte {
	return pk.raw[:]
}

// Hex returns the public key in hexstring.
func (pk *PublicKey448) Hex() string {
	return hex.EncodeToString(pk.Bytes())
}

// PrivateKey448 implements the PrivateKey interface.
type PrivateKey448 struct {
	raw [DHLEN448]byte
	pub *PublicKey448
}

// Bytes turns the underlying bytes array into a slice.
func (pk *PrivateKey448) Bytes() []byte {
	return pk.raw[:]
}

// DH performs a Diffie-Hellman calculation between the private key in the
// key pair and the public key.
func (pk *PrivateKey448) DH(pub PublicKey) ([]byte, error) {
	// replace the interface's value for public key
	pubKey, ok := pub.(*PublicKey448)
	if !ok {
		return nil, ErrMismatchedPublicKey
	}

	var shared [DHLEN448]byte
	curve448.ScalarMult(&shared, &pk.raw, &pubKey.raw)
	return shared[:], nil
}

// PubKey returns the corresponding public key.
func (pk *PrivateKey448) PubKey() PublicKey {
	return pk.pub
}

// Update writes secret to the private key.
func (pk *PrivateKey448) Update(data []byte) {
	copy(pk.raw[:], data[:DHLEN448])

	// calcuate the public key
	curve448.ScalarBaseMult(&pk.pub.raw, &pk.raw)
}

// Curve448 implements the DH interface(aka "X448").
type Curve448 struct {
	DHLEN int
}

// GenerateKeyPair creates a key pair from entropy. If the entropy is not
// supplied, it will use rand.Read to generate a new private key.
func (dh *Curve448) GenerateKeyPair(entropy []byte) (PrivateKey, error) {
	secret := make([]byte, DHLEN448)

	if entropy != nil {
		// entropy is given, use it to create the private key.
		copy(secret, entropy[:DHLEN448])
	} else {
		// no entropy given, use the default rand.Read.
		if _, err := rand.Read(secret); err != nil {
			return nil, err
		}
	}

	// set the raw data for both private and public keys.
	priv := &PrivateKey448{pub: &PublicKey448{}}
	priv.Update(secret)
	return priv, nil
}

// Size returns the DHLEN.
func (dh *Curve448) Size() int {
	return dh.DHLEN
}

func (dh *Curve448) String() string {
	return "448"
}

func init() {
	Register(X448.String(), X448)
}
