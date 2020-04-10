package cipher

import (
	"crypto/cipher"
	"encoding/binary"

	"golang.org/x/crypto/chacha20poly1305"
)

// NonceSizeChaChaPoly specifies the 12-byte nonce used by the cipher.
const NonceSizeChaChaPoly = 12

// ChaChaPoly is an instance of ChaChaPolyCipher, exported as supported ciphers.
var ChaChaPoly AEAD = &ChaChaPolyCipher{}

// ChaChaPolyCipher implements the Cipher interface.
type ChaChaPolyCipher struct {
	cipher cipher.AEAD
}

// Cipher returns the AEAD attached in the struct.
func (ccpc *ChaChaPolyCipher) Cipher() cipher.AEAD {
	return ccpc.cipher
}

// EncodeNonce encodes the nonce from an 8-byte unsigned integer into a 12-byte
// slice. The 96-bit nonce is formed by encoding 32 bits of zeros followed by
// little-endian encoding of n.
func (ccpc *ChaChaPolyCipher) EncodeNonce(n uint64) []byte {
	var nonce [NonceSizeChaChaPoly]byte
	binary.LittleEndian.PutUint64(nonce[4:], n)
	return nonce[:]
}

// Encrypt calls the underlying Seal function to create the ciphertext.
func (ccpc *ChaChaPolyCipher) Encrypt(n uint64, ad [ADSize]byte,
	plaintext []byte) ([]byte, error) {
	// nonce must be less than 2^64-1
	if n == MaxNonce {
		return nil, ErrNonceOverflow
	}

	nonce := ccpc.EncodeNonce(n)
	ciphertext := ccpc.Cipher().Seal(nil, nonce, plaintext, ad[:])
	return ciphertext, nil
}

// Decrypt calls the underlying Seal function to extract the plaintext.
func (ccpc *ChaChaPolyCipher) Decrypt(n uint64, ad [ADSize]byte,
	ciphertext []byte) ([]byte, error) {
	// nonce must be less than 2^64-1
	if n == MaxNonce {
		return nil, ErrNonceOverflow
	}

	nonce := ccpc.EncodeNonce(n)
	plaintext, err := ccpc.Cipher().Open(nil, nonce, ciphertext, ad[:])
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// InitCipher creates a new cipher and attach it to ChaChaPolyCipher.
func (ccpc *ChaChaPolyCipher) InitCipher(key [KeySize]byte) error {
	// New will return an error iff the key size is wrong. Because we enforce
	// it to be 32-byte, it's safe to ignore the error.
	ChaChaPoly, _ := chacha20poly1305.New(key[:])

	ccpc.cipher = ChaChaPoly
	return nil
}

func (ccpc *ChaChaPolyCipher) String() string {
	return "ChaChaPoly"
}

func init() {
	Register(ChaChaPoly.String(), ChaChaPoly)
}
