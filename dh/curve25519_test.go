// Test vectors taken from https://asecuritysite.com/encryption/go_25519test
package dh_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	. "github.com/yyforyongyu/noise/dh"
)

func TestGenerateKeyPair25519(t *testing.T) {

	var (
		priv = [32]byte{
			0xa8, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0x6b,
		}

		pubHex = "e3712d851a0e5d79b831c5e34ab22b41a198171de209b8b8faca23a11c" +
			"624859"
		pub = [32]byte{
			0xe3, 0x71, 0x2d, 0x85, 0x1a, 0xe, 0x5d, 0x79,
			0xb8, 0x31, 0xc5, 0xe3, 0x4a, 0xb2, 0x2b, 0x41,
			0xa1, 0x98, 0x17, 0x1d, 0xe2, 0x9, 0xb8, 0xb8,
			0xfa, 0xca, 0x23, 0xa1, 0x1c, 0x62, 0x48, 0x59,
		}
	)

	// supply 32-byte entropy
	privKey, _ := X25519.GenerateKeyPair(priv[:])

	require.Equal(t, priv[:], privKey.Bytes(),
		"private keys not match")
	require.Equal(t, pub[:], privKey.PubKey().Bytes(),
		"public keys not match")
	require.Equal(t, pubHex, privKey.PubKey().Hex(),
		"public key string doesn't match")

	// make an entropy greater than 32-byte. The function should only take the
	// first 32-byte.
	var extra []byte
	extra = append(extra, priv[:]...)
	extra = append(extra, byte(0x01))
	privKey, _ = X25519.GenerateKeyPair(extra)

	require.Equal(t, priv[:], privKey.Bytes(),
		"private keys not match")
	require.Equal(t, pub[:], privKey.PubKey().Bytes(),
		"public keys not match")
	require.Equal(t, pubHex, privKey.PubKey().Hex(),
		"public key string doesn't match")

	// no entropy passed, it should generate a new key pair.
	privKey, _ = X25519.GenerateKeyPair(nil)

	// weak check, as long as the keys changed, it'll pass
	require.NotEqual(t, priv[:], privKey.Bytes(),
		"private keys should not match")
	require.NotEqual(t, pub[:], privKey.PubKey().Bytes(),
		"public keys should not match")
	require.NotEqual(t, pubHex, privKey.PubKey().Hex(),
		"public key string should not match")

	// call it again and check that it indeed is "random"
	newprivKey, _ := X25519.GenerateKeyPair(nil)
	require.NotEqual(t, privKey.Bytes(), newprivKey.Bytes(),
		"private keys should not match")
	require.NotEqual(t, privKey.PubKey().Bytes(), newprivKey.PubKey().Bytes(),
		"public keys should not match")
	require.NotEqual(t, privKey.PubKey().Hex(), newprivKey.PubKey().Hex(),
		"public key string should not match")
}

func TestCurveSetUp25519(t *testing.T) {
	require.Equal(t, 32, X25519.Size(), "Curve25519's DHLEN must be 32")
	require.Equal(t, "25519", X25519.String(), "name must be 25519")
}

func TestDH25519(t *testing.T) {

	var (
		EMPTY []byte = nil

		alicePriv = [32]byte{
			0x77, 0x7, 0x6d, 0xa, 0x73, 0x18, 0xa5, 0x7d,
			0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
			0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
			0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
		}
		alicePub = [32]byte{
			0x85, 0x20, 0xf0, 0x9, 0x89, 0x30, 0xa7, 0x54,
			0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
			0xd, 0xbf, 0x3a, 0xd, 0x26, 0x38, 0x1a, 0xf4,
			0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a,
		}
		alicePrivKey, _ = X25519.GenerateKeyPair(alicePriv[:])

		bobPriv = [32]byte{
			0x5d, 0xab, 0x8, 0x7e, 0x62, 0x4a, 0x8a, 0x4b,
			0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0xe, 0xe6,
			0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
			0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb,
		}
		bobPub = [32]byte{
			0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
			0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
			0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
			0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f,
		}
		bobPrivKey, _ = X25519.GenerateKeyPair(bobPriv[:])

		shared = [32]byte{
			0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1,
			0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0xf, 0x25,
			0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33,
			0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42,
		}
	)
	// when public key is wrong, an error is returned
	invalidPub := &invalid{[1]byte{byte(1)}}
	secret, err := alicePrivKey.DH(invalidPub)
	require.Equal(t, EMPTY, secret,
		"when public is wrong, no key pair should return")
	require.Equal(t, ErrMismatchedPublicKey, err,
		"wrong error returned")

	// check from Alice's view
	secret, err = alicePrivKey.DH(bobPrivKey.PubKey())
	require.Equal(t, bobPub[:], bobPrivKey.PubKey().Bytes(),
		"bob's public keys do not match")
	require.Equal(t, shared[:], secret,
		"the shared secrets from alice's DH do not match")

	// check from Bob's view
	secret, err = bobPrivKey.DH(alicePrivKey.PubKey())
	require.Equal(t, alicePub[:], alicePrivKey.PubKey().Bytes(),
		"alice's public keys do not match")
	require.Equal(t, shared[:], secret,
		"the shared secrets from bob's DH do not match")

}
