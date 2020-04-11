package cipher_test

import (
	"fmt"
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
	aesgcm := cipher.FromString("AESGCM")
	aesgcm.InitCipher(key)

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
	ChaChaPoly := cipher.FromString("ChaChaPoly")
	ChaChaPoly.InitCipher(key)

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

func TestSetUp(t *testing.T) {
	// check supported curves
	require.NotNil(t, cipher.FromString("AESGCM"), "missing AESGCM")
	require.NotNil(t, cipher.FromString("ChaChaPoly"), "missing ChaChaPoly")

	// check return empty
	require.Nil(t, cipher.FromString("yy"), "yy does not exist, yet")

	require.Equal(t, len("AESGCM, ChaChaPoly"),
		len(cipher.SupportedCiphers()),
		"cipher AESGCM, ChaChaPoly should be returned")
}
func ExampleFromString() {
	// load cipher AESGCM
	aesgcm := cipher.FromString("AESGCM")
	fmt.Println(aesgcm)

	// load cipher ChaChaPoly
	ccp := cipher.FromString("ChaChaPoly")
	fmt.Println(ccp)
}
