package cipher

import (
	"crypto/cipher"
	"encoding/binary"

	"golang.org/x/crypto/chacha20poly1305"
)

// nonceSizechaChaPoly specifies the 12-byte nonce used by the cipher.
const nonceSizechaChaPoly = 12

// chaChaPolyCipher implements the Cipher interface.
type chaChaPolyCipher struct {
	cipher cipher.AEAD
}

// Cipher returns the AEAD attached in the struct.
func (ccpc *chaChaPolyCipher) Cipher() cipher.AEAD {
	return ccpc.cipher
}

// EncodeNonce encodes the nonce from an 8-byte unsigned integer into a 12-byte
// slice. The 96-bit nonce is formed by encoding 32 bits of zeros followed by
// little-endian encoding of n.
func (ccpc *chaChaPolyCipher) EncodeNonce(n uint64) []byte {
	var nonce [nonceSizechaChaPoly]byte
	binary.LittleEndian.PutUint64(nonce[4:], n)
	return nonce[:]
}

// Encrypt calls the underlying Seal function to create the ciphertext.
func (ccpc *chaChaPolyCipher) Encrypt(
	n uint64, ad, plaintext []byte) ([]byte, error) {
	// nonce must be less than 2^64-1
	if n == MaxNonce {
		return nil, ErrNonceOverflow
	}

	nonce := ccpc.EncodeNonce(n)
	ciphertext := ccpc.Cipher().Seal(nil, nonce, plaintext, ad)
	return ciphertext, nil
}

// Decrypt calls the underlying Seal function to extract the plaintext.
func (ccpc *chaChaPolyCipher) Decrypt(
	n uint64, ad, ciphertext []byte) ([]byte, error) {
	// nonce must be less than 2^64-1
	if n == MaxNonce {
		return nil, ErrNonceOverflow
	}

	nonce := ccpc.EncodeNonce(n)
	plaintext, err := ccpc.Cipher().Open(nil, nonce, ciphertext, ad)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// InitCipher creates a new cipher and attach it to chaChaPolyCipher.
func (ccpc *chaChaPolyCipher) InitCipher(key [KeySize]byte) error {
	// New will return an error iff the key size is wrong. Because we enforce
	// it to be 32-byte, it's safe to ignore the error.
	chaChaPoly, _ := chacha20poly1305.New(key[:])

	ccpc.cipher = chaChaPoly
	return nil
}

// Rekey updates the cipher's key by calling InitCipher, returns the new key.
//
// Note that instead of calling Encrypt as specified in the noise specs, it
// directly calls cipher.Seal to bypass the nonce and ad size check in Encrypt.
func (ccpc *chaChaPolyCipher) Rekey() [KeySize]byte {
	var newKey [KeySize]byte

	nonce := ccpc.EncodeNonce(MaxNonce)
	key := ccpc.Cipher().Seal(nil, nonce, ZEROS[:], ZEROLEN)
	copy(newKey[:], key)

	return newKey
}

// Reset removes the cipher.
func (ccpc *chaChaPolyCipher) Reset() {
	ccpc.cipher = nil
}

func (ccpc *chaChaPolyCipher) String() string {
	return "ChaChaPoly"
}

func newChaChaPoly() AEAD {
	return &chaChaPolyCipher{}
}

func init() {
	Register("ChaChaPoly", newChaChaPoly)
}
