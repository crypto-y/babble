package dh

import (
	"crypto/rand"
	"encoding/hex"

	curve "golang.org/x/crypto/curve25519"
)

// dhlen25519 defines the DHLEN for x25519.
const dhlen25519 = 32

// publicKey25519 implements the PublicKey interface.
type publicKey25519 struct {
	raw [dhlen25519]byte
}

// Bytes turns the underlying bytes array into a slice.
func (pk *publicKey25519) Bytes() []byte {
	return pk.raw[:]
}

// Hex returns the public key in hexstring.
func (pk *publicKey25519) Hex() string {
	return hex.EncodeToString(pk.Bytes())
}

// loadBytes takes the input data and copies it into a dhlen25519-byte array.
func (pk *publicKey25519) loadBytes(data []byte) error {
	if len(data) != dhlen25519 {
		return errMismatchedKey("public", dhlen25519, len(data))
	}
	copy(pk.raw[:], data)
	return nil
}

// privateKey25519 implements the PrivateKey interface.
type privateKey25519 struct {
	raw [dhlen25519]byte
	pub *publicKey25519
}

// Bytes turns the underlying byte array into a slice.
func (pk *privateKey25519) Bytes() []byte {
	return pk.raw[:]
}

// DH performs a Diffie-Hellman calculation between the private key itself and
// the public key.
func (pk *privateKey25519) DH(pub []byte) ([]byte, error) {
	var pubKey publicKey25519
	// validate public key
	if err := pubKey.loadBytes(pub); err != nil {
		return nil, err
	}

	var shared [dhlen25519]byte
	curve.ScalarMult(&shared, &pk.raw, &pubKey.raw)
	return shared[:], nil
}

// update writes secret to the private key.
func (pk *privateKey25519) update(data []byte) {
	copy(pk.raw[:], data[:dhlen25519])

	// calcuate the public key
	curve.ScalarBaseMult(&pk.pub.raw, &pk.raw)
}

// PubKey returns the corresponding public key.
func (pk *privateKey25519) PubKey() PublicKey {
	return pk.pub
}

// curve25519 implements the DH interface(aka "x25519").
type curve25519 struct {
	DHLEN int
}

// GenerateKeyPair creates a key pair from entropy. If the entropy is not
// supplied, it will use rand.Read to generate a new private key.
func (dh *curve25519) GenerateKeyPair(entropy []byte) (PrivateKey, error) {
	secret := make([]byte, dhlen25519)

	if entropy != nil {
		// entropy is given, use it to create the private key.
		copy(secret, entropy[:dhlen25519])
	} else {
		// no entropy given, use the default rand.Read.
		if _, err := rand.Read(secret); err != nil {
			return nil, err
		}
	}

	// set the raw data for both private and public keys.
	priv := &privateKey25519{pub: &publicKey25519{}}
	priv.update(secret)
	return priv, nil
}

// LoadPrivateKey uses the data provided to create a new private key.
func (dh *curve25519) LoadPrivateKey(data []byte) (PrivateKey, error) {
	p := &privateKey25519{pub: &publicKey25519{}}
	if len(data) != dhlen25519 {
		return nil, errMismatchedKey("private", dhlen25519, len(data))
	}
	p.update(data)
	return p, nil
}

// LoadPublicKey uses the data provided to create a new public key.
func (dh *curve25519) LoadPublicKey(data []byte) (PublicKey, error) {
	p := &publicKey25519{}
	if err := p.loadBytes(data); err != nil {
		return nil, err
	}
	return p, nil
}

// Size returns the DHLEN.
func (dh *curve25519) Size() int {
	return dh.DHLEN
}

func (dh *curve25519) String() string {
	return "25519"
}

func newCurve25519() Curve {
	return &curve25519{DHLEN: dhlen25519}
}

func init() {
	Register("25519", newCurve25519)
}
