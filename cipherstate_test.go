package noise

import (
	"testing"

	"github.com/stretchr/testify/require"
	noiseCipher "github.com/yyforyongyu/noise/cipher"
	"github.com/yyforyongyu/noise/rekey"
)

func TestCipherStateNoRekeyManager(t *testing.T) {
	alice := newCipherState(cipherA, nil)
	bob := newCipherState(cipherB, nil)

	// before init key, it should have no key and no rekey manager
	require.False(t, alice.HasKey(), "haskey must be false")
	require.Nil(t, alice.RekeyManger, "no rekey manager")
	require.False(t, bob.HasKey(), "haskey must be false")
	require.Nil(t, bob.RekeyManger, "no rekey manager")

	// init cipher state
	err := alice.InitializeKey(key)
	require.Nil(t, err, "init key without error")
	require.Equal(t, key, alice.key, "key should match")
	require.Equal(t, uint64(0), alice.nonce, "init key should set nonce to 0")

	bob.InitializeKey(key)

	// encrypt then decrypt
	ciphertext, err := alice.EncryptWithAd(ad, message)
	require.Nil(t, err, "encrypt without error")
	require.Equal(t, uint64(1), alice.nonce, "encrypt nonce increased once")

	plaintext, err := bob.DecryptWithAd(ad, ciphertext)
	require.Nil(t, err, "decrypt without error")
	require.Equal(t, message, plaintext, "wrong plaintext decrypted")
	require.Equal(t, uint64(1), bob.nonce, "decrypt nonce increased once")
	// en/decrypt again
	ciphertext, err = alice.EncryptWithAd(ad, message)
	require.Nil(t, err, "encrypt without error")
	require.Equal(t, uint64(2), alice.nonce, "encrypt nonce increased once")

	plaintext, err = bob.DecryptWithAd(ad, ciphertext)
	require.Nil(t, err, "decrypt without error")
	require.Equal(t, message, plaintext, "wrong plaintext decrypted")
	require.Equal(t, uint64(2), bob.nonce, "decrypt nonce increased once")

	// test rekey
	err = alice.Rekey()
	require.Nil(t, err, "rekey without error")
	require.NotEqual(t, key, alice.key, "rekey changes the cipher key")

	// test reset
	alice.Reset()
	require.Equal(t, uint64(0), alice.nonce, "reset sets nonce to be 0")
	require.Equal(t, ZEROS, alice.key, "reset sets key to be zeros")

	// test set nonce
	alice.SetNonce(maxNonce)
	require.Equal(t, maxNonce, alice.nonce, "noise should be equal")

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
	alice.InitializeKey(key)
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
	interval := 3

	rekeyerA := rekey.NewDefault(interval, cipherA, true)
	rekeyerB := rekey.NewDefault(interval, cipherB, true)
	alice := newCipherState(cipherA, rekeyerA)
	bob := newCipherState(cipherB, rekeyerB)
	alice.InitializeKey(key)
	bob.InitializeKey(key)

	// encrypt then decrypt
	ciphertext, err := alice.EncryptWithAd(ad, message)
	require.Nil(t, err, "encrypt without error")
	require.Equal(t, uint64(1), alice.nonce, "encrypt nonce increased once")
	require.Equal(t, key, alice.key, "alice's key should stay unchanged")

	plaintext, err := bob.DecryptWithAd(ad, ciphertext)
	require.Nil(t, err, "decrypt without error")
	require.Equal(t, message, plaintext, "wrong plaintext decrypted")
	require.Equal(t, uint64(1), bob.nonce, "decrypt nonce increased once")
	require.Equal(t, key, bob.key, "bob's key should stay unchanged")

	// encrypt and decrypt again
	ciphertext, err = alice.EncryptWithAd(ad, message)
	require.Nil(t, err, "encrypt without error")
	require.Equal(t, uint64(2), alice.nonce, "encrypt nonce increased once")
	require.Equal(t, key, alice.key, "alice's key should stay unchanged")

	plaintext, err = bob.DecryptWithAd(ad, ciphertext)
	require.Nil(t, err, "decrypt without error")
	require.Equal(t, message, plaintext, "wrong plaintext decrypted")
	require.Equal(t, uint64(2), bob.nonce, "decrypt nonce increased once")
	require.Equal(t, key, bob.key, "bob's key should stay unchanged")

	// encrypt then decrypt again will incur a rekey
	ciphertext, err = alice.EncryptWithAd(ad, message)
	require.Nil(t, err, "encrypt without error")
	require.Equal(
		t, uint64(0), alice.nonce, "alice's nonce should be zero after rekey")
	require.NotEqual(t, key, alice.key, "alice's key should be changed")

	plaintext, err = bob.DecryptWithAd(ad, ciphertext)
	require.Nil(t, err, "decrypt without error")
	require.Equal(
		t, uint64(0), bob.nonce, "bob's nonce should be zero after rekey")
	require.NotEqual(t, key, bob.key, "bob's key should be changed")
	require.Equal(t, message, plaintext, "wrong plaintext decrypted")

	// use a big nonce to cause an error in rekey
	alice.SetNonce(uint64(interval + 1))
	ciphertext, err = alice.EncryptWithAd(ad, message)
	require.Equal(t, rekey.ErrCorruptedNonce, err, "should return nonce corrupted")
	require.Nil(t, ciphertext, "no ciphertext encrypted")
}
