// Package cipher implements the cipher functions specified in the noise
// protocol.
//
// It currently supports two ciphers:
//  - ChaCha20Poly1350, which uses https://golang.org/x/crypto/chacha20poly1305.
//  - AESGCM, which uses https://pkg.go.dev/crypto/aes. Be cautious when using
//   this cipher as it might be vunlerable to side channel attack.
package cipher

import (
	"crypto/cipher"
	"errors"
	"fmt"
	"strings"
)

const (
	// ADSize defines the size of the ad(authentication data), in bytes.
	ADSize = 16

	// KeySize defines the size of the cipher key, in bytes.
	KeySize = 32

	// NonceSize defines the size of the nonce, an 8-byte unsigned integer.
	NonceSize = 8

	// MaxNonce is an 8-byte unsigned integer and equals to 2^64-1.
	MaxNonce = ^uint64(0)
)

var (
	// ErrNonceOverflow is used when the nonce exceeds the 2^64-1 limit.
	ErrNonceOverflow = errors.New("nonce is too big")

	supportedCiphers = map[string]AEAD{}
)

// AEAD specifies an interface for building a cipher used by the noise package.
type AEAD interface {
	fmt.Stringer

	// Cipher returns a cipher.AEAD. This function enforces that any cipher
	// implement this AEAD interface must also satisfy the cipher.AEAD.
	Cipher() cipher.AEAD

	// EncodeNonce turns the nonce used in the noise protocol into a format
	// that's accepted by the specific cipher specs.
	EncodeNonce(n uint64) []byte

	// Encrypt uses the cipher key k of 32 bytes and an 8-byte unsigned integer
	// nonce n which must be unique for the key k, and returns the ciphertext.
	// Encryption must be done with an "AEAD" encryption mode with the
	// associated data ad and returns a ciphertext that is the same size as the
	// plaintext plus 16 bytes for authentication data.
	Encrypt(n uint64, ad [ADSize]byte, plaintext []byte) ([]byte, error)

	// Decrypt uses a cipher key k of 32 bytes, an 8-byte unsigned integer nonce
	// n, and associated data ad, and returns the plaintext, unless
	// authentication fails, in which case an error is returned.
	Decrypt(n uint64, ad [ADSize]byte, ciphertext []byte) ([]byte, error)

	// InitCipher creates a cipher with the secret key.
	InitCipher(key [KeySize]byte) error
}

// FromString uses the provided cipher name, s, to query a built-in cipher.
func FromString(s string) AEAD {
	return supportedCiphers[s]
}

// Register updates the supported ciphers used in package cipher.
func Register(s string, a AEAD) {
	// TODO: check registry
	supportedCiphers[s] = a
}

// SupportedCiphers gives the names of all the ciphers registered. If no new
// ciphers are registered, it returns a string as "AESGCM, ChaChaPoly", orders
// not preserved.
func SupportedCiphers() string {
	keys := make([]string, 0, len(supportedCiphers))
	for k := range supportedCiphers {
		keys = append(keys, k)
	}
	return strings.Join(keys, ", ")
}
