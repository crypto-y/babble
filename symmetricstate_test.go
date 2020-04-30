package babble

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yyforyongyu/babble/cipher"
	noiseCipher "github.com/yyforyongyu/babble/cipher"
	noiseCurve "github.com/yyforyongyu/babble/dh"
	noiseHash "github.com/yyforyongyu/babble/hash"
)

func TestSymmetricState(t *testing.T) {
	var (
		cipherA, _ = noiseCipher.FromString("AESGCM")
		cipherB, _ = noiseCipher.FromString("AESGCM")

		hashA, _ = noiseHash.FromString("SHA256")
		hashB, _ = noiseHash.FromString("SHA256")

		curveA, _ = noiseCurve.FromString("25519")
		curveB, _ = noiseCurve.FromString("25519")

		csA = newCipherState(cipherA, nil)
		csB = newCipherState(cipherB, nil)

		key = [CipherKeySize]byte{
			0xa8, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0x6b,
		}

		message  = []byte("Noise Protocol Framework")
		maxNonce = cipher.MaxNonce

		protocolName     = []byte("TestNoise")
		longProtocolName = [1000]byte{}
	)

	alice := newSymmetricState(csA, hashA, curveA)
	bob := newSymmetricState(csB, hashB, curveB)

	// test encrypt then decrypt without init
	ciphertext, err := alice.EncryptAndHash(message)
	require.Nil(t, err, "encrypt without error")
	require.Equal(
		t, message, ciphertext, "ciphertext should be the same as plaintext")

	plaintext, err := bob.DecryptAndHash(ciphertext)
	require.Nil(t, err, "encrypt without error")
	require.Equal(
		t, ciphertext, plaintext, "plaintext should be the same as ciphertext")

	// init cipher state and test again
	csA.initializeKey(key)
	csB.initializeKey(key)
	ciphertext, err = alice.EncryptAndHash(message)
	require.Nil(t, err, "encrypt without error")

	plaintext, err = bob.DecryptAndHash(ciphertext)
	require.Nil(t, err, "encrypt without error")
	require.Equal(
		t, message, plaintext, "plaintext should be the same as ciphertext")

	// test GetHandshakeHash
	digest := alice.GetHandshakeHash()
	require.Equal(t, alice.digest, digest, "digest should match")

	// test encrypt/decrypt with error
	plaintext, err = bob.DecryptAndHash(ciphertext)
	require.NotNil(t, err, "decrypt should return an error")
	require.Nil(t, plaintext, "no plaintext decrypted whatsoever")

	alice.cs.nonce = maxNonce
	ciphertext, err = alice.EncryptAndHash(message)
	require.NotNil(t, err, "encrypt should return an error")
	require.Nil(t, plaintext, "no ciphertext encrypted whatsoever")

	// test InitializeSymmetric with weak check
	alice.InitializeSymmetric(protocolName)
	currentDigest := alice.digest
	require.Equal(t, ZEROS, alice.cs.key, "alice's cipher key is set to zeros")
	require.Equal(
		t, alice.hash.HashLen(), len(currentDigest), "digest length wrong")
	require.Equal(
		t, alice.digest, alice.chainingKey, "chaining key should be digest")

	// now init with the long name
	alice.InitializeSymmetric(longProtocolName[:])
	require.Equal(t, ZEROS, alice.cs.key, "alice's cipher key is set to zeros")
	require.NotEqual(t, currentDigest, alice.digest, "digest should change")
	require.Equal(
		t, alice.digest, alice.chainingKey, "chaining key should be digest")

}

func TestSymmetricStateHKDF(t *testing.T) {
	var (
		// outputs for testing HKDF, generated using the follow script,
		// https://cryptography.io/en/latest/development/custom-vectors/hkdf/
		// with the key defined here.
		key = [CipherKeySize]byte{
			0xa8, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0x6b,
		}
		output1 = []byte{
			0x85, 0x85, 0xab, 0xf7, 0x0, 0x92, 0xcf, 0x7b,
			0x82, 0x83, 0xb7, 0xe5, 0xb, 0x4a, 0x90, 0xe5,
			0x77, 0xa7, 0x50, 0xe9, 0x8c, 0x47, 0x16, 0x52,
			0xd9, 0x5b, 0xc0, 0xcd, 0xe3, 0x73, 0x8d, 0x41,
		}
		output2 = []byte{
			0x5d, 0x8, 0xce, 0x6d, 0x8c, 0x78, 0x2f, 0x90,
			0x43, 0x3c, 0x1e, 0xb9, 0x41, 0x6d, 0x95, 0x1,
			0x12, 0x1c, 0xe4, 0xcd, 0x2b, 0xde, 0x1b, 0x34,
			0xa9, 0x7d, 0xad, 0x10, 0xfd, 0x33, 0xb2, 0x2d,
		}
		output3 = []byte{
			0xcf, 0x3f, 0x1f, 0x45, 0x94, 0x57, 0x6, 0xa3,
			0x52, 0xdf, 0x54, 0x43, 0x63, 0xa7, 0x2f, 0x9a,
			0xf1, 0x44, 0x6d, 0x50, 0x2a, 0x36, 0x46, 0xe5,
			0x6a, 0xe, 0xe4, 0xbc, 0xad, 0x9f, 0x7, 0x3b,
		}

		cipherA, _ = noiseCipher.FromString("AESGCM")
		hashA, _   = noiseHash.FromString("SHA256")
		curveA, _  = noiseCurve.FromString("25519")
	)

	cs := newCipherState(cipherA, nil)
	ss := newSymmetricState(cs, hashA, curveA)

	// test HKDF with test vectors
	ss.chainingKey = ZEROS[:]
	outputSlice, err := ss.HKDF(key[:], 3)
	require.Nil(t, err, "hkdf should return no error")
	require.Equal(t, 3, len(outputSlice), "outputs len should be 3")
	require.Equal(t, output1, outputSlice[0], "first output should match")
	require.Equal(t, output2, outputSlice[1], "second output should match")
	require.Equal(t, output3, outputSlice[2], "third output should match")

	// test HKDF with errors
	ss.chainingKey = nil
	outputSlice, err = ss.HKDF(key[:], 1)
	require.Equal(t, errInvalidHKDFNum, err, "should return errInvalidHKDFNum")
	require.Nil(t, outputSlice, "no outputs should return")

	outputSlice, err = ss.HKDF([]byte{1}, 2)
	require.Equal(t, errInvalidKeySize, err, "should return errInvalidKeySize")
	require.Nil(t, outputSlice, "no outputs should return")

	outputSlice, err = ss.HKDF(key[:], 2)
	require.Equal(
		t, errInvalidChainingKey, err, "should return errInvalidChainingKey")
	require.Nil(t, outputSlice, "no outputs should return")

	// test MixHash with weak check
	ss.MixHash(key[:])
	require.Equal(
		t, ss.hash.HashLen(), len(ss.digest), "digest size should match")

	// test MixKey
	ss.chainingKey = ZEROS[:]
	err = ss.MixKey(key[:])
	require.Nil(t, err, "mix key should return no error")
	require.Equal(t, output1, ss.chainingKey, "chaining key should be output1")
	require.Equal(t, output2, ss.cs.key[:], "cipher key should be output2")

	// use wrong size key cause an error
	err = ss.MixKey([]byte{1})
	require.NotNil(t, err, "mix key should return an error")

	// test MixKeyAndHash
	ss.chainingKey = ZEROS[:]
	err = ss.MixKeyAndHash(key[:])
	require.Nil(t, err, "MixKeyAndHash should return no error")
	require.Equal(t, output1, ss.chainingKey, "chaining key should be output1")
	require.Equal(t, output3, ss.cs.key[:], "cipher key should be output3")
	require.Equal(
		t, ss.hash.HashLen(), len(ss.digest), "digest size should match")

	// use wrong size key cause an error
	err = ss.MixKeyAndHash([]byte{1})
	require.NotNil(t, err, "MixKeyAndHash should return an error")

	// reset chaining key
	ss.Reset()
	require.Equal(
		t, ZEROLEN, ss.chainingKey, "reset chainging key should be nil")
	require.Nil(t, ss.cs, "cs should be nil")
}

func TestSymmetricStateSplit(t *testing.T) {
	var (
		// outputs for testing HKDF, generated using the follow script,
		// https://cryptography.io/en/latest/development/custom-vectors/hkdf/
		// with the key ZEROLEN.
		output1 = []byte{
			0xeb, 0x70, 0xf0, 0x1d, 0xed, 0xe9, 0xaf, 0xaf,
			0xa4, 0x49, 0xee, 0xe1, 0xb1, 0x28, 0x65, 0x4,
			0xe1, 0xf6, 0x23, 0x88, 0xb3, 0xf7, 0xdd, 0x4f,
			0x95, 0x66, 0x97, 0xb0, 0xe8, 0x28, 0xfe, 0x18,
		}
		output2 = []byte{
			0x1e, 0x59, 0xc2, 0xec, 0xf, 0xe6, 0xe7, 0xe7,
			0xac, 0x26, 0x13, 0xb6, 0xab, 0x65, 0x34, 0x2a,
			0x83, 0x37, 0x99, 0x69, 0xda, 0x23, 0x42, 0x40,
			0xcd, 0xed, 0x37, 0x77, 0x91, 0x4d, 0xb9, 0x7,
		}

		cipherA, _ = noiseCipher.FromString("AESGCM")
		hashA, _   = noiseHash.FromString("SHA256")
		curveA, _  = noiseCurve.FromString("25519")
	)

	cs := newCipherState(cipherA, nil)
	ss := newSymmetricState(cs, hashA, curveA)

	// wrong chainging key causes an error
	c1, c2, err := ss.Split()
	require.Equal(
		t, errInvalidChainingKey, err, "should return errInvalidChainingKey")

	// set chainingkey to be zeros
	ss.chainingKey = ZEROS[:]
	c1, c2, err = ss.Split()
	require.Nil(t, err, "should return no error")
	require.Equal(t, output1, c1.key[:], "c1 should use output1 as cipher key")
	require.Equal(t, output2, c2.key[:], "c2 should use output2 as cipher key")
}
