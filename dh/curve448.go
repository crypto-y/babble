package dh

import (
	"crypto/rand"
	"encoding/hex"

	curve "gitlab.com/yawning/x448.git"
)

// dhlen448 defines the DHLEN for x448.
const dhlen448 = 56

// publicKey448 implements the PublicKey interface.
type publicKey448 struct {
	raw [dhlen448]byte
}

// Bytes turns the underlying bytes array into a slice.
func (pk *publicKey448) Bytes() []byte {
	return pk.raw[:]
}

// LoadBytes takes the input data and copies it into a dhlen448-byte array.
func (pk *publicKey448) LoadBytes(data []byte) error {
	if len(data) != dhlen448 {
		return ErrMismatchedPublicKey
	}
	copy(pk.raw[:], data)
	return nil
}

// Hex returns the public key in hexstring.
func (pk *publicKey448) Hex() string {
	return hex.EncodeToString(pk.Bytes())
}

// privateKey448 implements the PrivateKey interface.
type privateKey448 struct {
	raw [dhlen448]byte
	pub *publicKey448
}

// Bytes turns the underlying bytes array into a slice.
func (pk *privateKey448) Bytes() []byte {
	return pk.raw[:]
}

// DH performs a Diffie-Hellman calculation between the private key in the
// key pair and the public key.
func (pk *privateKey448) DH(pub []byte) ([]byte, error) {
	var pubKey publicKey448
	// validate public key
	if err := pubKey.LoadBytes(pub); err != nil {
		return nil, err
	}

	var shared [dhlen448]byte
	curve.ScalarMult(&shared, &pk.raw, &pubKey.raw)
	return shared[:], nil
}

// PubKey returns the corresponding public key.
func (pk *privateKey448) PubKey() PublicKey {
	return pk.pub
}

// Update writes secret to the private key.
func (pk *privateKey448) Update(data []byte) {
	copy(pk.raw[:], data[:dhlen448])

	// calcuate the public key
	curve.ScalarBaseMult(&pk.pub.raw, &pk.raw)
}

// curve448 implements the DH interface(aka "X448").
type curve448 struct {
	DHLEN int
}

// GenerateKeyPair creates a key pair from entropy. If the entropy is not
// supplied, it will use rand.Read to generate a new private key.
func (c *curve448) GenerateKeyPair(entropy []byte) (PrivateKey, error) {
	secret := make([]byte, dhlen448)

	if entropy != nil {
		// entropy is given, use it to create the private key.
		copy(secret, entropy[:dhlen448])
	} else {
		// no entropy given, use the default rand.Read.
		if _, err := rand.Read(secret); err != nil {
			return nil, err
		}
	}

	// set the raw data for both private and public keys.
	priv := &privateKey448{pub: &publicKey448{}}
	priv.Update(secret)
	return priv, nil
}

// Size returns the DHLEN.
func (c *curve448) Size() int {
	return c.DHLEN
}

func (c *curve448) String() string {
	return "448"
}

func newCurve448() Curve {
	return &curve448{DHLEN: dhlen448}
}

func init() {
	Register("448", newCurve448)
}
