# Cipher Functions
This package implements the cipher functions specified in the [noise protocol framework](https://noiseprotocol.org).



# Built-in Ciphers
Two cipher functions are supported, as specified in the [noise specs](https://noiseprotocol.org/noise.html#cipher-functions).

1. [AESGCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode)

   AESGCM is implemented based upon the official Go cipher package `crypto/aes`. Use it with caution though, as the AES operations in the `crypto/aes` package are not implemented using constant-time algorithms, which makes it vunerable to [side channel attack](https://en.wikipedia.org/wiki/Side-channel_attack).

   However, if the package is running on systems with [hardware support for AES](https://en.wikipedia.org/wiki/AES_instruction_set) then it won't be an issue. More details can be found following this [discussion](https://github.com/golang/go/issues/16821).

   As for this package, AESGCM is tuned based on the [noise specs](https://noiseprotocol.org/noise.html#the-aesgcm-cipher-functions):

   > AES256 with GCM with a 128-bit tag appended to the ciphertext. The 96-bit nonce is formed by encoding 32 bits of zeros followed by big-endian encoding of n.

2. [ChaChaPoly](https://tools.ietf.org/html/rfc7539)

   ChaChaPoly is implemented based on `golang.org/x/crypto/chacha20poly1305` by using the ChaCha20-Poly1305 AEAD.



# Customized Cipher Functions

To create your own cipher function, you'll need to implement the interface specified in [`cipher.go`](https://github.com/yyforyongyu/noise/blob/master/cipher/cipher.go). Once implemented, you need to register it using `Register(Name, Cipher)`.

An example customized implementation, which implements the `ChaChaPolyX`.

```go
package main

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"

	noiseCipher "github.com/yyforyongyu/noise/cipher"
	"golang.org/x/crypto/chacha20poly1305"
)

// NewCipher implements the Cipher interface.
type NewCipher struct {
	aead cipher.AEAD
}

// Cipher returns the AEAD attached in the struct.
func (nc *NewCipher) Cipher() cipher.AEAD {
	return nc.aead
}

// EncodeNonce encodes the nonce from an 8-byte unsigned integer into a 24-byte
// slice. The 96-bit nonce is formed by encoding 128 bits of zeros followed by
// little-endian encoding of n.
func (nc *NewCipher) EncodeNonce(n uint64) []byte {
	var nonce [chacha20poly1305.NonceSizeX]byte
	binary.LittleEndian.PutUint64(nonce[16:], n)
	return nonce[:]
}

// Encrypt calls the underlying Seal function to create the ciphertext.
func (nc *NewCipher) Encrypt(n uint64, ad [16]byte,
	plaintext []byte) ([]byte, error) {
	// nonce must be less than 2^64-1
	if n == noiseCipher.MaxNonce {
		return nil, noiseCipher.ErrNonceOverflow
	}

	nonce := nc.EncodeNonce(n)
	ciphertext := nc.Cipher().Seal(nil, nonce, plaintext, ad[:])
	return ciphertext, nil
}

// Decrypt calls the underlying Seal function to extract the plaintext.
func (nc *NewCipher) Decrypt(n uint64, ad [16]byte,
	ciphertext []byte) ([]byte, error) {
	// nonce must be less than 2^64-1
	if n == noiseCipher.MaxNonce {
		return nil, noiseCipher.ErrNonceOverflow
	}

	nonce := nc.EncodeNonce(n)
	plaintext, err := nc.Cipher().Open(nil, nonce, ciphertext, ad[:])
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// InitCipher creates a new cipher and attach it to NewCipher.
func (nc *NewCipher) InitCipher(key [32]byte) error {
	ChaChaPolyX, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return err
	}

	nc.aead = ChaChaPolyX
	return nil
}

func (nc *NewCipher) String() string {
	return "ChaChaPolyX"
}

func main() {
	var ChaChaPolyX noiseCipher.AEAD = &NewCipher{}

	// Register it for package noise.
	noiseCipher.Register(ChaChaPolyX.String(), ChaChaPolyX)

	// Once registered, inside the package noise, it can be called as,
	// noiseCipher.FromString("ChaChaPolyX")
	fmt.Println(noiseCipher.FromString("ChaChaPolyX"))
}
```

