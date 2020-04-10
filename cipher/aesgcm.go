package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
)

// NonceSizeAESGCM specifies the 12-byte nonce used by the cipher.
const NonceSizeAESGCM = 12

// AESGCM is the instance of AESGCMCipher, exported as supported ciphers.
var AESGCM AEAD = &AESGCMCipher{}

// AESGCMCipher implements the Cipher interface.
type AESGCMCipher struct {
	cipher cipher.AEAD
}

// Cipher returns the AEAD attached in the struct.
func (agc *AESGCMCipher) Cipher() cipher.AEAD {
	return agc.cipher
}

// EncodeNonce encodes the nonce from an 8-byte unsigned integer into a 12-byte
// slice. The 12-byte nonce is formed by encoding 32 bits of zeros followed
// by big-endian encoding of n.
func (agc *AESGCMCipher) EncodeNonce(n uint64) []byte {
	var nonce [NonceSizeAESGCM]byte
	binary.BigEndian.PutUint64(nonce[4:], n)
	return nonce[:]
}

// Encrypt calls the underlying Seal function to create the ciphertext.
func (agc *AESGCMCipher) Encrypt(n uint64, ad [ADSize]byte,
	plaintext []byte) ([]byte, error) {
	// nonce must be less than 2^64-1
	if n == MaxNonce {
		return nil, ErrNonceOverflow
	}

	nonce := agc.EncodeNonce(n)
	ciphertext := agc.Cipher().Seal(nil, nonce, plaintext, ad[:])
	return ciphertext, nil
}

// Decrypt calls the underlying Seal function to extract the plaintext.
func (agc *AESGCMCipher) Decrypt(n uint64, ad [ADSize]byte,
	ciphertext []byte) ([]byte, error) {
	// nonce must be less than 2^64-1
	if n == MaxNonce {
		return nil, ErrNonceOverflow
	}

	nonce := agc.EncodeNonce(n)
	plaintext, err := agc.Cipher().Open(nil, nonce, ciphertext, ad[:])
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// InitCipher creates a new cipher and attach it to AESGCMCipher.
func (agc *AESGCMCipher) InitCipher(key [KeySize]byte) error {
	// NewCipher will return an error iff the key size is wrong. So we ignore
	// the error because the key size is fixed 32 byte.
	block, _ := aes.NewCipher(key[:])

	// NewGCM will return an error if tagSize or BlockSize of the cipher is
	// wrong. Because the default tagSize and built-in AES are used, it's safe
	// to ignore the error.
	aesgcm, _ := cipher.NewGCM(block)

	agc.cipher = aesgcm
	return nil
}

func (agc *AESGCMCipher) String() string {
	return "AESGCM"
}

func init() {
	Register(AESGCM.String(), AESGCM)
}
