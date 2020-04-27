package noise

import (
	"reflect"

	"errors"

	noiseCipher "github.com/yyforyongyu/noise/cipher"
	"github.com/yyforyongyu/noise/rekey"
)

// CipherKeySize defines the bytes of the key.
const CipherKeySize = 32

var (
	// ZEROS is a 32-byte array filled with zeros.
	ZEROS [CipherKeySize]byte

	// ZEROLEN is a zero-length byte sequence.
	ZEROLEN []byte

	errMissingCipherKey = errors.New("No cipher key initialized")
)

// cipherState contains key and nonce variables, which it uses to encrypt and
// decrypt ciphertext. During the handshake phase each party has a single
// cipherState, but during the transport phase each party has two cipherState
// instances, one for sending, and one for receiving.
type cipherState struct {
	// Rekeyer is a customized rekey function.
	RekeyManger rekey.Rekeyer

	// A cipher key of 32 bytes (which may be zeros). zeros is a special
	// value which indicates the key has not yet been initialized.
	//
	// cipherKey is the k in the noise specs.
	key [CipherKeySize]byte

	// An 8-byte (64-bit) unsigned integer nonce.
	//
	// nonce is the n in the noise specs.
	nonce uint64

	// cipher is an AEAD defined from package noise/cipher.
	cipher noiseCipher.AEAD
}

// DecryptWithAd decrypts ciphertext with ad. If the key is non-empty it returns
// the decrypted plaintext, otherwise returns ciphertext.
//
// If an authentication failure occurs in decryption then nonce is not
// incremented and an error is signaled to the caller.
func (cs *cipherState) DecryptWithAd(ad, ciphertext []byte) ([]byte, error) {
	if !cs.HasKey() {
		return ciphertext, nil
	}

	plaintext, err := cs.cipher.Decrypt(cs.nonce, ad, ciphertext)
	if err != nil {
		return nil, err
	}

	// increment and check the nonce
	//
	// The error should be safe to ignore here, as if the nonce is incorrect,
	// Decrypt will have already returned an error above.
	if err := cs.incrementNonce(); err != nil {
		return nil, err
	}

	return plaintext, nil
}

// EncryptWithAd encrypts plaintext with ad. If the key is non-empty it returns
// the encrypted ciphertext, otherwise returns plaintext.
func (cs *cipherState) EncryptWithAd(ad, plaintext []byte) ([]byte, error) {
	if !cs.HasKey() {
		return plaintext, nil
	}

	ciphertext, err := cs.cipher.Encrypt(cs.nonce, ad, plaintext)
	if err != nil {
		return nil, err
	}

	// increment and check the nonce
	if err := cs.incrementNonce(); err != nil {
		return nil, err
	}

	return ciphertext, nil
}

// HashKey returns true if cipher key is not empty, otherwise false.
func (cs *cipherState) HasKey() bool {
	return !reflect.DeepEqual(cs.key, ZEROS)
}

// InitializeKey sets the cipher key and nonce.
func (cs *cipherState) InitializeKey(k [CipherKeySize]byte) error {
	// clean cipher state first
	cs.Reset()

	copy(cs.key[:], k[:])
	if err := cs.cipher.InitCipher(cs.key); err != nil {
		return err
	}
	return nil
}

// Rekey updates the underlying cipher with a new key. If a rekeyer is defined
// for the cipherstate, it's used to generate the new key. Otherwise, it uses
// the Rekey from the underlying cipher to generate a new key.
//
// There are actually two places to customize a Rekey function. First here, then
// there's an opportunity in the underlying cipher.Rekey().
// Also note that Rekey only updates the cipher's key value, it doesn't reset the
// cipher's nonce value, so applications performing Rekey must still perform
// a new handshake if sending 2^64 or more transport messages.
func (cs *cipherState) Rekey() error {
	if !cs.HasKey() {
		// Must have been initialized before
		return errMissingCipherKey
	}
	var newKey [CipherKeySize]byte

	if cs.RekeyManger != nil {
		// use it if a rekeyer is defined
		newKey = cs.RekeyManger.Rekey(cs.key[:])
	} else {
		// use the default rekey from the cipher
		newKey = cs.cipher.Rekey()
	}

	// update the cipher without resetting the nonce.
	copy(cs.key[:], newKey[:])
	if err := cs.cipher.InitCipher(cs.key); err != nil {
		return err
	}
	return nil
}

// Reset sets the cipher key to ZEROS, nonce to 0, and calls cipher.Reset.
func (cs *cipherState) Reset() {
	cs.key = ZEROS
	cs.nonce = 0
	cs.cipher.Reset()
}

// SetNonce sets the nonce. This function is used for handling out-of-order
// transport messages
func (cs *cipherState) SetNonce(n uint64) {
	cs.nonce = n
}

// incrementNonce increments and checks the nonce. When it reaches the value of
// RekeyInterval, a rekey is performed.
func (cs *cipherState) incrementNonce() error {
	cs.nonce++

	// if no RekeyManger is attached, abort.
	if cs.RekeyManger == nil {
		return nil
	}

	// use customized logic from RekeyManger to check whether a Rekey is needed.
	need, err := cs.RekeyManger.CheckRekey(cs.nonce)
	if err != nil {
		return err
	}
	if need {
		cs.Rekey()
		if cs.RekeyManger.ResetNonce() {
			cs.nonce = 0
		}
	}

	return nil
}

func newCipherState(
	cipher noiseCipher.AEAD, rekeyer rekey.Rekeyer) *cipherState {
	return &cipherState{
		cipher:      cipher,
		RekeyManger: rekeyer,
	}
}
