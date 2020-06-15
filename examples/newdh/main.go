// This is an implemention for demonstration only. DON'T USE IT IN YOUR CODE.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"github.com/crypto-y/babble/dh"
)

// DHLEN must be >= 32.
const DHLEN = 32

// DumbPublicKey implements the PublicKey interface.
type DumbPublicKey struct {
	raw [DHLEN]byte
}

// Bytes turns the underlying bytes array into a slice.
func (pk *DumbPublicKey) Bytes() []byte {
	return pk.raw[:]
}

// LoadBytes takes the input data and copies it into a DHLEN-byte array.
func (pk *DumbPublicKey) LoadBytes(data []byte) error {
	if len(data) != DHLEN {
		return errors.New("public key size mismatched")
	}
	copy(pk.raw[:], data)
	return nil
}

// Hex returns the public key in hexstring.
func (pk *DumbPublicKey) Hex() string {
	return hex.EncodeToString(pk.Bytes())
}

// DumbPrivateKey implements the PrivateKey interface.
type DumbPrivateKey struct {
	raw [DHLEN]byte
	pub *DumbPublicKey
}

// Bytes turns the underlying bytes array into a slice.
func (pk *DumbPrivateKey) Bytes() []byte {
	return pk.raw[:]
}

// DH performs a Diffie-Hellman calculation between the private key in the
// key pair and the public key.
func (pk *DumbPrivateKey) DH(pub []byte) ([]byte, error) {
	var pubKey DumbPublicKey
	// validate public key
	if err := pubKey.LoadBytes(pub); err != nil {
		return nil, err
	}

	var shared []byte
	// This is for demonstration only.
	// An XOR here won't do anything, and you should replace it with a secure
	// cryptographic function.
	for i, b := range pk.Bytes() {
		xorByte := pubKey.Bytes()[i] ^ b
		shared = append(shared, xorByte)
	}
	return shared, nil
}

// PubKey returns the corresponding public key.
func (pk *DumbPrivateKey) PubKey() dh.PublicKey {
	return pk.pub
}

// Update writes secret to the private key.
func (pk *DumbPrivateKey) Update(data []byte) {
	copy(pk.raw[:], data[:DHLEN])

	// This is for demonstration only.
	// We just sort the bytes in the private key.
	copy(pk.pub.raw[:], pk.raw[:])
	sort.Slice(pk.pub.raw[:], func(i, j int) bool {
		return pk.pub.raw[i] < pk.pub.raw[j]
	})
}

// DumbCurve implements the DH interface.
type DumbCurve struct {
	DHLEN int
}

// GenerateKeyPair creates a key pair from entropy. If the entropy is not
// supplied, it will use rand.Read to generate a new private key.
func (c *DumbCurve) GenerateKeyPair(entropy []byte) (dh.PrivateKey, error) {
	secret := make([]byte, DHLEN)

	if entropy != nil {
		// entropy is given, use it to create the private key.
		copy(secret, entropy[:DHLEN])
	} else {
		// no entropy given, use the default rand.Read.
		if _, err := rand.Read(secret); err != nil {
			return nil, err
		}
	}

	// set the raw data for both private and public keys.
	priv := &DumbPrivateKey{pub: &DumbPublicKey{}}
	priv.Update(secret)
	return priv, nil
}

// LoadPrivateKey uses the data provided to create a new private key.
func (c *DumbCurve) LoadPrivateKey(data []byte) (dh.PrivateKey, error) {
	p := &DumbPrivateKey{pub: &DumbPublicKey{}}
	if len(data) != DHLEN {
		return nil, errors.New("private key size mismatched")
	}
	p.Update(data)
	return p, nil
}

// LoadPublicKey uses the data provided to create a new public key.
func (c *DumbCurve) LoadPublicKey(data []byte) (dh.PublicKey, error) {
	p := &DumbPublicKey{}
	if err := p.LoadBytes(data); err != nil {
		return nil, err
	}
	return p, nil
}

// Size returns the DHLEN.
func (c *DumbCurve) Size() int {
	return c.DHLEN
}

func (c *DumbCurve) String() string {
	return "Dumb"
}

func newDumbCurve() dh.Curve {
	return &DumbCurve{DHLEN: DHLEN}
}

func main() {
	// dumb implements the DH interface for DumbCurve.
	dh.Register("Dumb", newDumbCurve)

	dumb, _ := dh.FromString("Dumb")
	fmt.Println("registered curve: ", dumb)
}
