package noise

import (
	"errors"

	noiseCipher "github.com/yyforyongyu/noise/cipher"
)

// DefaultRekeyInterval is used when RekeyInterval is unset.
const DefaultRekeyInterval = noiseCipher.MaxNonce

var errCorruptedNonce = errors.New("Nonce is corrupted, please reset")

// Rekeyer defines a customized Rekey function to be used when rotating cipher
// key.

// Rekey doesn't reset n to zero because:

// Leaving n unchanged is simple.

// If the cipher has a weakness such that repeated rekeying gives rise to a cycle of keys, then letting n advance will avoid catastrophic reuse of the same k and n values.

// Letting n advance puts a bound on the total number of encryptions that can be performed with a set of derived keys.
type Rekeyer interface {
	Rekey(key []byte) [CipherKeySize]byte

	CheckRekey(nonce uint64) (bool, error)

	ResetNonce() bool
}

type defaultRekeyer struct {
	// RekeyInterval defines the number of messages sent before changing the
	// cipher key by calling Rekey. If it's not set, then the key's never
	// changed.
	RekeyInterval uint64
	cipher        noiseCipher.AEAD
	resetNonce    bool
}

func newDefault(interval int, cipher noiseCipher.AEAD, resetNonce bool) Rekeyer {
	return &defaultRekeyer{
		RekeyInterval: uint64(interval),
		cipher:        cipher,
		resetNonce:    resetNonce,
	}
}

func (d *defaultRekeyer) Rekey([]byte) [CipherKeySize]byte {
	// use the default rekey from the cipher
	return d.cipher.Rekey()
}

func (d *defaultRekeyer) ResetNonce() bool {
	return d.resetNonce
}

func (d *defaultRekeyer) SetRekeyInterval(n int) error {
	if uint64(n) >= noiseCipher.MaxNonce {
		return noiseCipher.ErrNonceOverflow
	}
	d.RekeyInterval = uint64(n)
	return nil
}

func (d *defaultRekeyer) CheckRekey(n uint64) (bool, error) {
	// if nonce is greater than the value, it must be corrupted.
	// Maybe this could happen from calling cipherState.SetNonce.
	if n > d.RekeyInterval {
		return false, errCorruptedNonce
	}

	// when nonce reaches a given value, performs a rekey.
	if n == d.RekeyInterval {
		return true, nil
	}

	return false, nil
}
