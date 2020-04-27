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
func (nc *NewCipher) Encrypt(n uint64, ad, plaintext []byte) ([]byte, error) {
	// nonce must be less than 2^64-1
	if n == noiseCipher.MaxNonce {
		return nil, noiseCipher.ErrNonceOverflow
	}

	nonce := nc.EncodeNonce(n)
	ciphertext := nc.Cipher().Seal(nil, nonce, plaintext, ad)
	return ciphertext, nil
}

// Decrypt calls the underlying Seal function to extract the plaintext.
func (nc *NewCipher) Decrypt(n uint64, ad, ciphertext []byte) ([]byte, error) {
	// nonce must be less than 2^64-1
	if n == noiseCipher.MaxNonce {
		return nil, noiseCipher.ErrNonceOverflow
	}

	nonce := nc.EncodeNonce(n)
	plaintext, err := nc.Cipher().Open(nil, nonce, ciphertext, ad)
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

// Rekey updates the cipher's key by calling InitCipher.
func (nc *NewCipher) Rekey() [noiseCipher.KeySize]byte {
	var newKey [32]byte

	nonce := nc.EncodeNonce(noiseCipher.MaxNonce)
	key := nc.Cipher().Seal(
		nil, nonce, noiseCipher.ZEROS[:], noiseCipher.ZEROLEN)
	copy(newKey[:], key)

	return newKey
}

// Reset removes the cipher.
func (nc *NewCipher) Reset() {
	nc.aead = nil
}

func (nc *NewCipher) String() string {
	return "ChaChaPolyX"
}

func newCipher() noiseCipher.AEAD {
	return &NewCipher{}
}

func main() {
	// Register it for package noise.
	noiseCipher.Register("ChaChaPolyX", newCipher)

	// Once registered, inside the package noise, it can be called as,
	// noiseCipher.FromString("ChaChaPolyX")
	c, _ := noiseCipher.FromString("ChaChaPolyX")
	fmt.Println(c)
}
