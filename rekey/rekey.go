// Package rekey defines the rekey functions to be used in the babbel package.
// For any customized rekey functions, the Rekeyer must be statisfied. Once
// created, the rekeyer should be passed into the ProtocolConfig used in the
// noise package.
package rekey

import (
	"errors"

	noiseCipher "github.com/crypto-y/babble/cipher"
)

// CipherKeySize defines the byte length of the key returned from Rekey.
const CipherKeySize = 32

var (
	errCorruptedNonce  = errors.New("Nonce is corrupted, please reset")
	errInvalidInterval = errors.New("invalid interval value")
)

// Rekeyer defines a customized Rekey function to be used when rotating cipher
// key.
type Rekeyer interface {
	// Rekey creates a new key. The old key can be accessed using cipher.key if
	// the implementation uses algorithms which relies on the old cipher key to
	// create the new key. A 32-byte key is returned.
	Rekey() [CipherKeySize]byte

	// CheckRekey implements the logic to decide whether a rekey should be
	// performed based on the given nonce. Other customized logic unrelated to
	// the nonce can also be implemented.
	CheckRekey(nonce uint64) (bool, error)

	// ResetNonce tells the caller whether the cipher nonce should be reset to
	// zero.
	ResetNonce() bool

	// Interval returns the number of messages to be sent before a rekey is
	// performed.
	Interval() uint64
}

type defaultRekeyer struct {
	// RekeyInterval defines the number of messages sent before changing the
	// cipher key by calling Rekey. If it's not set, then the key's never
	// changed.
	RekeyInterval uint64
	cipher        noiseCipher.AEAD
	resetNonce    bool
	count         uint64
}

// NewDefault creates a default rekeyer defined by the noise protocol. It
// returns a 32-byte key from calling the Rekey function defined in the cipher,
// which is the result of ENCRYPT(k, maxnonce, zerolen, zeros), where maxnonce
// equals 2^64-1, zerolen is a zero-length byte sequence, and zeros is a
// sequence of 32 bytes filled with zeros.
//
// The parameter interval specifies after how many messages a rekey is
// performed, and the resetNonce decides whether the nonce should be reset to
// zero when performing rekey.
func NewDefault(interval uint64, cipher noiseCipher.AEAD,
	resetNonce bool) Rekeyer {
	return &defaultRekeyer{
		RekeyInterval: uint64(interval),
		cipher:        cipher,
		resetNonce:    resetNonce,
	}
}

func (d *defaultRekeyer) Rekey() [CipherKeySize]byte {
	// use the default rekey from the cipher
	// TODO: rm dependency on cipher
	return d.cipher.Rekey()
}

func (d *defaultRekeyer) ResetNonce() bool {
	return d.resetNonce
}

func (d *defaultRekeyer) CheckRekey(n uint64) (bool, error) {
	// increase count
	d.count = n % d.RekeyInterval

	// If resetNonce is true and nonce is greater than the value, it must be
	// corrupted.
	// This could happen from calling cipherState.SetNonce.
	if d.resetNonce && n > d.RekeyInterval {
		return false, errCorruptedNonce
	}

	// when count reaches a given value, a rekey needs to be performed.
	if d.count == uint64(0) {
		return true, nil
	}

	return false, nil
}

func (d *defaultRekeyer) Interval() uint64 {
	return d.RekeyInterval
}
