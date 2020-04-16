package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
)

// nonceSizeaESGCM specifies the 12-byte nonce used by the cipher.
const nonceSizeaESGCM = 12

// aESGCMCipher implements the Cipher interface.
type aESGCMCipher struct {
	cipher cipher.AEAD
}

// Cipher returns the AEAD attached in the struct.
func (agc *aESGCMCipher) Cipher() cipher.AEAD {
	return agc.cipher
}

// EncodeNonce encodes the nonce from an 8-byte unsigned integer into a 12-byte
// slice. The 12-byte nonce is formed by encoding 32 bits of zeros followed
// by big-endian encoding of n.
func (agc *aESGCMCipher) EncodeNonce(n uint64) []byte {
	var nonce [nonceSizeaESGCM]byte
	binary.BigEndian.PutUint64(nonce[4:], n)
	return nonce[:]
}

// Encrypt calls the underlying Seal function to create the ciphertext.
func (agc *aESGCMCipher) Encrypt(
	n uint64, ad, plaintext []byte) ([]byte, error) {
	// nonce must be less than 2^64-1
	if n == MaxNonce {
		return nil, ErrNonceOverflow
	}

	nonce := agc.EncodeNonce(n)
	ciphertext := agc.Cipher().Seal(nil, nonce, plaintext, ad)
	return ciphertext, nil
}

// Decrypt calls the underlying Seal function to extract the plaintext.
func (agc *aESGCMCipher) Decrypt(
	n uint64, ad, ciphertext []byte) ([]byte, error) {
	// nonce must be less than 2^64-1
	if n == MaxNonce {
		return nil, ErrNonceOverflow
	}

	nonce := agc.EncodeNonce(n)
	plaintext, err := agc.Cipher().Open(nil, nonce, ciphertext, ad)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// InitCipher creates a new cipher and attach it to aESGCMCipher.
func (agc *aESGCMCipher) InitCipher(key [KeySize]byte) error {
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

// Rekey creates a new cipher's key and returns it, without updating the cipher.
//
// Note that instead of calling Encrypt as specified in the noise specs, it
// directly calls cipher.Seal to bypass the nonce and ad size check in Encrypt.
func (agc *aESGCMCipher) Rekey() [KeySize]byte {
	var newKey [KeySize]byte

	nonce := agc.EncodeNonce(MaxNonce)
	key := agc.Cipher().Seal(nil, nonce, ZEROS[:], ZEROLEN)
	copy(newKey[:], key)

	return newKey
}

// Reset removes the cipher.
func (agc *aESGCMCipher) Reset() {
	agc.cipher = nil
}

func (agc *aESGCMCipher) String() string {
	return "AESGCM"
}

func init() {
	// aESGCM is the instance of aESGCMCipher, exported as supported ciphers.
	var aesgcm AEAD = &aESGCMCipher{}

	Register(aesgcm.String(), aesgcm)
}
