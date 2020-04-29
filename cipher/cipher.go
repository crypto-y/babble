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
	// // ADSize defines the size of the ad(authentication data), in bytes.
	// ADSize = 16

	// KeySize defines the size of the cipher key, in bytes.
	KeySize = 32

	// // NonceSize defines the size of the nonce, an 8-byte unsigned integer.
	// NonceSize = 8

	// MaxNonce is an 8-byte unsigned integer and equals to 2^64-1.
	MaxNonce = ^uint64(0)
)

var (
	// ErrNonceOverflow is used when the nonce exceeds the 2^64-1 limit.
	ErrNonceOverflow = errors.New("nonce is too big")

	// ZEROLEN is a zero-length byte sequence.
	ZEROLEN []byte

	// ZEROS is a 32-byte array filled with zeros.
	ZEROS [KeySize]byte

	supportedCiphers = map[string]NewCipher{}
)

// NewCipher returns an instance of a cipher.
type NewCipher func() AEAD

// AEAD specifies an interface for building a cipher used by the babbel package.
type AEAD interface {
	fmt.Stringer

	// Cipher returns a cipher.AEAD. This function enforces that any cipher
	// implement this AEAD interface must also satisfy the cipher.AEAD.
	Cipher() cipher.AEAD

	// Decrypt uses a cipher key k of 32 bytes, an 8-byte unsigned integer nonce
	// n, and associated data ad, and returns the plaintext, unless
	// authentication fails, in which case an error is returned.
	Decrypt(n uint64, ad, ciphertext []byte) ([]byte, error)

	// EncodeNonce turns the nonce used in the noise protocol into a format
	// that's accepted by the specific cipher specs.
	EncodeNonce(n uint64) []byte

	// Encrypt uses the cipher key k of 32 bytes and an 8-byte unsigned integer
	// nonce n which must be unique for the key k, and returns the ciphertext.
	// Encryption must be done with an "AEAD" encryption mode with the
	// associated data ad and returns a ciphertext that is the same size as the
	// plaintext plus 16 bytes for authentication data.
	Encrypt(n uint64, ad, plaintext []byte) ([]byte, error)

	// InitCipher creates a cipher with the secret key.
	InitCipher(key [KeySize]byte) error

	// Rekey creates a new 32-byte cipher key as a pseudorandom function of key.
	// It returns the first 32 bytes from calling Encrypt with,
	//  - n as maxnonce, which equals 2^64-1,
	//  - ad as zerolen, a zero-length byte sequence,
	//  - plaintext as zeros, a sequence of 32 bytes filled with zeros.
	Rekey() [KeySize]byte

	// Reset cleans all the states to zero value, if any.
	Reset()
}

// FromString uses the provided cipher name, s, to query a built-in cipher.
func FromString(s string) (AEAD, error) {
	if supportedCiphers[s] != nil {
		return supportedCiphers[s](), nil
	}
	return nil, errUnsupported(s)
}

// Register updates the supported ciphers used in package cipher.
func Register(s string, f NewCipher) {
	// TODO: check registry

	// check the AEAD interface is matched
	var _ AEAD = f()

	supportedCiphers[s] = f
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

func errUnsupported(s string) error {
	return fmt.Errorf("cipher: %s is unsupported", s)
}
