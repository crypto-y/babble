package cipher_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yyforyongyu/noise/cipher"
)

var (
	key = [cipher.KeySize]byte{
		0xa8, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
		0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
		0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
		0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0x6b,
	}
	ad = [cipher.ADSize]byte{
		0xa8, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
		0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
	}
	nonce   = uint64(1)
	message = []byte("Noise Protocol Framework")
)

func TestAESGCM(t *testing.T) {
	aesgcm := cipher.AESGCM
	aesgcm.InitCipher(key)

	// check setup
	require.Equal(t, "AESGCM", aesgcm.String(), "name should be AESGCM")

	// first we encrypt the message
	ciphertext, _ := aesgcm.Encrypt(nonce, ad, message)
	// then we decrypt the ciphertext, the returned value should equal message
	plaintext, _ := aesgcm.Decrypt(nonce, ad, ciphertext)
	require.Equal(t, message, plaintext, "AESGCM failed to encrypt/decrypt")

	// use a max nonce to trigger the overflow error
	_, err := aesgcm.Encrypt(cipher.MaxNonce, ad, message)
	require.Equal(t, cipher.ErrNonceOverflow, err,
		"Nonce overflow error not returned")
	_, err = aesgcm.Decrypt(cipher.MaxNonce, ad, message)
	require.Equal(t, cipher.ErrNonceOverflow, err,
		"Nonce overflow error not returned")

	// use a short ciphertext to trigger an error when Open it
	wrongCiphertext := []byte{}
	_, err = aesgcm.Decrypt(nonce, ad, wrongCiphertext)
	require.NotNil(t, err, "Open a wrong ciphertext should return an error")
}

func TestChaChaPoly(t *testing.T) {
	ChaChaPoly := cipher.ChaChaPoly
	ChaChaPoly.InitCipher(key)

	// check setup
	require.Equal(t, "ChaChaPoly", ChaChaPoly.String(),
		"name should be ChaChaPoly")

	// first we encrypt the message
	ciphertext, _ := ChaChaPoly.Encrypt(nonce, ad, message)
	// then we decrypt the ciphertext, the returned value should equal message
	plaintext, _ := ChaChaPoly.Decrypt(nonce, ad, ciphertext)
	require.Equal(t, message, plaintext, "ChaChaPoly failed to encrypt/decrypt")

	// use a max nonce to trigger the overflow error
	_, err := ChaChaPoly.Encrypt(cipher.MaxNonce, ad, message)
	require.Equal(t, cipher.ErrNonceOverflow, err,
		"Nonce overflow error not returned")
	_, err = ChaChaPoly.Decrypt(cipher.MaxNonce, ad, message)
	require.Equal(t, cipher.ErrNonceOverflow, err,
		"Nonce overflow error not returned")

	// use a short ciphertext to trigger an error when Open it
	wrongCiphertext := []byte{}
	_, err = ChaChaPoly.Decrypt(nonce, ad, wrongCiphertext)
	require.NotNil(t, err, "Open a wrong ciphertext should return an error")
}

func TestFromString(t *testing.T) {
	// check supported curves
	require.Equal(t, cipher.AESGCM, cipher.FromString("AESGCM"),
		"missing AESGCM")
	require.Equal(t, cipher.ChaChaPoly, cipher.FromString("ChaChaPoly"),
		"missing ChaChaPoly")

	// check return empty
	require.Nil(t, cipher.FromString("yy"), "yy does not exist, yet")
}
