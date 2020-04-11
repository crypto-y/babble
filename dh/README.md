# DH Functions

This package implements the DH functions, as specified in the noise specs.

### Built-in Curves

The following curves are supported,

**[Curve25519](https://en.wikipedia.org/wiki/Curve25519)**

The protocol name is `25519`, e.g., Noise_XX_**25519**\_AESGCM_SHA256.

**[Curve448](https://en.wikipedia.org/wiki/Curve448)**

The protocol name is `448`, e.g., Noise_XX_**448**\_AESGCM_SHA256.

**[Secp256k1](https://en.bitcoin.it/wiki/Secp256k1)**

The protocol name is `secp256k1`, e.g., Noise_XX_**secp256k1**\_AESGCM_SHA256.



### Customized DH function

To create your own DH function, you'll need to implement the interfaces specified in [`dh.go`](https://github.com/yyforyongyu/noise/blob/master/dh/dh.go), which requires a  `PublicKey` interface, a `PrivateKey` interface and a `Curve` interface. And you need to register it using `Register(Name, Curve)`.

Here's an example, which implements a curve named `dumb`, which does nothing.

```go
// This is an implemention for demonstration only. DON'T USE IT IN YOUR CODE.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/yyforyongyu/noise/dh"
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
		return dh.ErrMismatchedPublicKey
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

// Size returns the DHLEN.
func (c *DumbCurve) Size() int {
	return c.DHLEN
}

func (c *DumbCurve) String() string {
	return "Dumb"
}

func main() {
	// dumb implements the DH interface for DumbCurve.
	var dumb dh.Curve = &DumbCurve{DHLEN: DHLEN}
	dh.Register(dumb.String(), dumb)

	fmt.Println("registered curve: ", dumb)
}
```

