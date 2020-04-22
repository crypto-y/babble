// Test vectors taken generated from btcec
package dh_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yyforyongyu/noise/dh"
)

var secp256k1, _ = dh.FromString("secp256k1")

func TestGenerateKeyPairBitcoin(t *testing.T) {

	var (
		priv = [32]byte{
			0x1a, 0xc3, 0x6f, 0x20, 0xbd, 0xfa, 0xe1, 0xc6,
			0x5a, 0x9c, 0x25, 0x9f, 0x94, 0x2f, 0x24, 0x45,
			0xbb, 0xa1, 0xd, 0xd3, 0xb, 0xf5, 0xd7, 0x3a,
			0xad, 0x7c, 0x8a, 0x4b, 0x41, 0x6d, 0x1c, 0x9e,
		}

		pubHex = "02f8b43166457e4267ac22541b5ab617956433aa9a8b264abb28dc9949" +
			"fa9708e0"
		pub = [33]byte{
			0x2, 0xf8, 0xb4, 0x31, 0x66, 0x45, 0x7e, 0x42,
			0x67, 0xac, 0x22, 0x54, 0x1b, 0x5a, 0xb6, 0x17,
			0x95, 0x64, 0x33, 0xaa, 0x9a, 0x8b, 0x26, 0x4a,
			0xbb, 0x28, 0xdc, 0x99, 0x49, 0xfa, 0x97, 0x8,
			0xe0,
		}
	)

	// supply 32-byte entropy
	privKey, _ := secp256k1.GenerateKeyPair(priv[:])

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
	privKey, _ = secp256k1.GenerateKeyPair(extra)

	require.Equal(t, priv[:], privKey.Bytes(),
		"private keys not match")
	require.Equal(t, pub[:], privKey.PubKey().Bytes(),
		"public keys not match")
	require.Equal(t, pubHex, privKey.PubKey().Hex(),
		"public key string doesn't match")

	// no entropy passed, it should generate a new key pair.
	privKey, _ = secp256k1.GenerateKeyPair(nil)

	// weak check, as long as the keys changed, it'll pass
	require.NotEqual(t, priv[:], privKey.Bytes(),
		"private keys should not match")
	require.NotEqual(t, pub[:], privKey.PubKey().Bytes(),
		"public keys should not match")
	require.NotEqual(t, pubHex, privKey.PubKey().Hex(),
		"public key string should not match")

	// call it again and check that it indeed is "random"
	newprivKey, _ := secp256k1.GenerateKeyPair(nil)
	require.NotEqual(t, privKey.Bytes(), newprivKey.Bytes(),
		"private keys should not match")
	require.NotEqual(t, privKey.PubKey().Bytes(), newprivKey.PubKey().Bytes(),
		"public keys should not match")
	require.NotEqual(t, privKey.PubKey().Hex(), newprivKey.PubKey().Hex(),
		"public key string should not match")
}

func TestCurveSetUpBitcoin(t *testing.T) {
	require.Equal(t, 32, secp256k1.Size(), "CurveBitcoin's DHLEN must be 32")
	require.Equal(t, "secp256k1", secp256k1.String(), "name must be secp256k1")
}

func TestDHBitcoin(t *testing.T) {

	var (
		EMPTY []byte = nil

		alicePriv = [32]byte{
			0x1a, 0xc3, 0x6f, 0x20, 0xbd, 0xfa, 0xe1, 0xc6,
			0x5a, 0x9c, 0x25, 0x9f, 0x94, 0x2f, 0x24, 0x45,
			0xbb, 0xa1, 0xd, 0xd3, 0xb, 0xf5, 0xd7, 0x3a,
			0xad, 0x7c, 0x8a, 0x4b, 0x41, 0x6d, 0x1c, 0x9e,
		}
		alicePub = [33]byte{
			0x2, 0xf8, 0xb4, 0x31, 0x66, 0x45, 0x7e, 0x42,
			0x67, 0xac, 0x22, 0x54, 0x1b, 0x5a, 0xb6, 0x17,
			0x95, 0x64, 0x33, 0xaa, 0x9a, 0x8b, 0x26, 0x4a,
			0xbb, 0x28, 0xdc, 0x99, 0x49, 0xfa, 0x97, 0x8,
			0xe0,
		}

		alicePrivKey, _ = secp256k1.GenerateKeyPair(alicePriv[:])

		bobPriv = [32]byte{
			0xeb, 0x94, 0xa, 0x6a, 0x5b, 0x3e, 0x80, 0x75,
			0x15, 0x1e, 0x2c, 0x35, 0x9b, 0xe8, 0x67, 0x4f,
			0xb8, 0x6a, 0x6, 0x58, 0xa3, 0xc6, 0x45, 0x8,
			0x46, 0x68, 0x2, 0xf3, 0x53, 0x2c, 0x96, 0xc2,
		}
		bobPub = [33]byte{
			0x2, 0xb, 0x19, 0x50, 0x7b, 0x75, 0xe2, 0xe0,
			0xcb, 0x55, 0x61, 0xba, 0x8c, 0xbf, 0xdb, 0x6d,
			0x94, 0x2, 0xb8, 0x8b, 0x7a, 0xc, 0x4a, 0x58,
			0x9e, 0x25, 0x3f, 0xf, 0x22, 0x82, 0x78, 0x63,
			0xee,
		}
		bobPrivKey, _ = secp256k1.GenerateKeyPair(bobPriv[:])

		shared = [32]byte{
			0xc8, 0x1a, 0x74, 0x4b, 0xbc, 0x5c, 0x67, 0x2f,
			0x9f, 0x83, 0x5c, 0x3b, 0x99, 0x15, 0x13, 0x97,
			0x44, 0xb5, 0xdb, 0xd5, 0xbc, 0x51, 0xe2, 0x99,
			0x11, 0xab, 0x7a, 0x1b, 0x3b, 0x8c, 0xc8, 0x6a,
		}
	)
	// when public key is wrong, an error is returned
	secret, err := alicePrivKey.DH(invalidPub)
	require.Equal(t, EMPTY, secret,
		"when public is wrong, no key pair should return")
	require.Equal(t, dh.ErrMismatchedPublicKey, err,
		"wrong error returned")

	// check from Alice's view
	secret, err = alicePrivKey.DH(bobPub[:])
	require.Nil(t, err, "should not return an error")
	require.Equal(t, bobPub[:], bobPrivKey.PubKey().Bytes(),
		"bob's public keys do not match")
	require.Equal(t, shared[:], secret,
		"the shared secrets from alice's DH do not match")

	// check from Bob's view
	secret, err = bobPrivKey.DH(alicePub[:])
	require.Nil(t, err, "should not return an error")
	require.Equal(t, alicePub[:], alicePrivKey.PubKey().Bytes(),
		"alice's public keys do not match")
	require.Equal(t, shared[:], secret,
		"the shared secrets from bob's DH do not match")

}
