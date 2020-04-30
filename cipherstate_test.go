package babble

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yyforyongyu/babble/cipher"
	noiseCipher "github.com/yyforyongyu/babble/cipher"
	"github.com/yyforyongyu/babble/rekey"
)

func TestCipherStateNoRekeyManager(t *testing.T) {
	var (
		cipherA, _ = noiseCipher.FromString("AESGCM")
		cipherB, _ = noiseCipher.FromString("AESGCM")

		key = [CipherKeySize]byte{
			0xa8, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0x6b,
		}

		ad = []byte{
			0xa8, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
		}
		message  = []byte("Noise Protocol Framework")
		maxNonce = cipher.MaxNonce
	)

	alice := newCipherState(cipherA, nil)
	bob := newCipherState(cipherB, nil)

	// before init key, it should have no key and no rekey manager
	require.False(t, alice.hasKey(), "haskey must be false")
	require.Nil(t, alice.RekeyManger, "no rekey manager")
	require.False(t, bob.hasKey(), "haskey must be false")
	require.Nil(t, bob.RekeyManger, "no rekey manager")

	// init cipher state
	err := alice.initializeKey(key)
	require.Nil(t, err, "init key without error")
	require.Equal(t, key, alice.key, "key should match")
	require.Equal(t, uint64(0), alice.Nonce(), "init key should set nonce to 0")

	bob.initializeKey(key)

	// encrypt then decrypt
	ciphertext, err := alice.EncryptWithAd(ad, message)
	require.Nil(t, err, "encrypt without error")
	require.Equal(t, uint64(1), alice.Nonce(), "encrypt nonce increased once")

	plaintext, err := bob.DecryptWithAd(ad, ciphertext)
	require.Nil(t, err, "decrypt without error")
	require.Equal(t, message, plaintext, "wrong plaintext decrypted")
	require.Equal(t, uint64(1), bob.Nonce(), "decrypt nonce increased once")
	// en/decrypt again
	ciphertext, err = alice.EncryptWithAd(ad, message)
	require.Nil(t, err, "encrypt without error")
	require.Equal(t, uint64(2), alice.Nonce(), "encrypt nonce increased once")

	plaintext, err = bob.DecryptWithAd(ad, ciphertext)
	require.Nil(t, err, "decrypt without error")
	require.Equal(t, message, plaintext, "wrong plaintext decrypted")
	require.Equal(t, uint64(2), bob.Nonce(), "decrypt nonce increased once")

	// test rekey
	err = alice.Rekey()
	require.Nil(t, err, "rekey without error")
	require.NotEqual(t, key, alice.key, "rekey changes the cipher key")

	// test reset
	alice.Reset()
	require.Equal(t, uint64(0), alice.Nonce(), "reset sets nonce to be 0")
	require.Equal(t, ZEROS, alice.key, "reset sets key to be zeros")

	// test set nonce
	alice.SetNonce(maxNonce)
	require.Equal(t, maxNonce, alice.Nonce(), "nonce should be equal")

	// alice has no key, both encrypt/decrypt should return plaintext
	ciphertext, err = alice.EncryptWithAd(ad, message)
	require.Nil(t, err, "encrypt without error")
	require.Equal(t, message, ciphertext, "message is not encrypted")
	plaintext, err = alice.DecryptWithAd(ad, message)
	require.Nil(t, err, "decrypt without error")
	require.Equal(t, message, plaintext, "message is not decrypted")
	// rekey now gives an error
	err = alice.Rekey()
	require.Equal(
		t, errMissingCipherKey, err, "should return errMissingCipherKey")

	// test encrypt errors
	alice.initializeKey(key)
	alice.SetNonce(maxNonce)
	ciphertext, err = alice.EncryptWithAd(ad, message)
	require.Equal(
		t, noiseCipher.ErrNonceOverflow, err, "should return nonce overflow")
	require.Nil(t, ciphertext, "no ciphertext encrypted")

	// test decrypt errors
	plaintext, err = bob.DecryptWithAd(ad, message)
	require.Nil(t, plaintext, "no plaintext decrypted")
	require.NotNil(t, err, "decrypt should return an error")
}

func TestCipherStateDefaultRekeyManager(t *testing.T) {
	var (
		cipherA, _ = noiseCipher.FromString("AESGCM")
		cipherB, _ = noiseCipher.FromString("AESGCM")

		key = [CipherKeySize]byte{
			0xa8, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0x6b,
		}

		ad = []byte{
			0xa8, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
		}
		message = []byte("Noise Protocol Framework")
	)

	interval := uint64(3)

	rekeyerA := rekey.NewDefault(interval, cipherA, true)
	rekeyerB := rekey.NewDefault(interval, cipherB, true)
	alice := newCipherState(cipherA, rekeyerA)
	bob := newCipherState(cipherB, rekeyerB)
	alice.initializeKey(key)
	bob.initializeKey(key)

	// encrypt then decrypt
	ciphertext, err := alice.EncryptWithAd(ad, message)
	require.Nil(t, err, "encrypt without error")
	require.Equal(t, uint64(1), alice.Nonce(), "encrypt nonce increased once")
	require.Equal(t, key, alice.key, "alice's key should stay unchanged")

	plaintext, err := bob.DecryptWithAd(ad, ciphertext)
	require.Nil(t, err, "decrypt without error")
	require.Equal(t, message, plaintext, "wrong plaintext decrypted")
	require.Equal(t, uint64(1), bob.Nonce(), "decrypt nonce increased once")
	require.Equal(t, key, bob.key, "bob's key should stay unchanged")

	// encrypt and decrypt again
	ciphertext, err = alice.EncryptWithAd(ad, message)
	require.Nil(t, err, "encrypt without error")
	require.Equal(t, uint64(2), alice.Nonce(), "encrypt nonce increased once")
	require.Equal(t, key, alice.key, "alice's key should stay unchanged")

	plaintext, err = bob.DecryptWithAd(ad, ciphertext)
	require.Nil(t, err, "decrypt without error")
	require.Equal(t, message, plaintext, "wrong plaintext decrypted")
	require.Equal(t, uint64(2), bob.Nonce(), "decrypt nonce increased once")
	require.Equal(t, key, bob.key, "bob's key should stay unchanged")

	// encrypt then decrypt again will incur a rekey
	ciphertext, err = alice.EncryptWithAd(ad, message)
	require.Nil(t, err, "encrypt without error")
	require.Equal(
		t, uint64(0), alice.Nonce(), "alice's nonce should be zero after rekey")
	require.NotEqual(t, key, alice.key, "alice's key should be changed")

	plaintext, err = bob.DecryptWithAd(ad, ciphertext)
	require.Nil(t, err, "decrypt without error")
	require.Equal(
		t, uint64(0), bob.Nonce(), "bob's nonce should be zero after rekey")
	require.NotEqual(t, key, bob.key, "bob's key should be changed")
	require.Equal(t, message, plaintext, "wrong plaintext decrypted")

	// use a big nonce to cause an error in rekey
	alice.SetNonce(uint64(interval + 1))
	ciphertext, err = alice.EncryptWithAd(ad, message)
	require.Equal(t, "Nonce is corrupted, please reset", err.Error(),
		"should return nonce corrupted")
	require.Nil(t, ciphertext, "no ciphertext encrypted")
}
