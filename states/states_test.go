package noise

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yyforyongyu/noise/cipher"
	noiseCipher "github.com/yyforyongyu/noise/cipher"
	noiseCurve "github.com/yyforyongyu/noise/dh"
	noiseHash "github.com/yyforyongyu/noise/hash"
)

var (
	cipherA, _ = noiseCipher.FromString("AESGCM")
	cipherB, _ = noiseCipher.FromString("AESGCM")

	hashA, _ = noiseHash.FromString("SHA256")
	hashB, _ = noiseHash.FromString("SHA256")

	curveA, _ = noiseCurve.FromString("25519")
	curveB, _ = noiseCurve.FromString("25519")

	csA = newCipherState(cipherA, nil)
	ssA = newSymmetricState(csA, hashA, curveA)

	csB = newCipherState(cipherB, nil)
	ssB = newSymmetricState(csB, hashB, curveB)

	key = [CipherKeySize]byte{
		0xa8, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
		0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
		0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
		0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0x6b,
	}
	pubBitcoin = [33]byte{
		0x2, 0xf8, 0xb4, 0x31, 0x66, 0x45, 0x7e, 0x42,
		0x67, 0xac, 0x22, 0x54, 0x1b, 0x5a, 0xb6, 0x17,
		0x95, 0x64, 0x33, 0xaa, 0x9a, 0x8b, 0x26, 0x4a,
		0xbb, 0x28, 0xdc, 0x99, 0x49, 0xfa, 0x97, 0x8,
		0xe0,
	}
	ad = []byte{
		0xa8, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
		0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
	}
	message  = []byte("Noise Protocol Framework")
	maxNonce = cipher.MaxNonce

	protocolName = []byte("TestNoise")
	prologue     = []byte("YY")
	psk          = []byte{
		0xa8, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
		0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
		0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
		0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0x6b,
	}
	pskToken = [][]byte{psk}
)

func TestHandshakeState(t *testing.T) {
	// with psk
	// with payload
	// ???

	// Pattern used for testing,
	// -> e
	// <- e, ee
	// -> s, se
	plaintext := []byte("yyforyongyu")
	sAlice, _ := curveA.GenerateKeyPair(nil)
	sBob, _ := curveB.GenerateKeyPair(nil)

	alice, err := newHandshakeState(protocolName, prologue, pskToken,
		true, ssA, XN, sAlice, nil, nil, nil)
	require.Nil(t, err, "alice failed to create handshake state")

	bob, err := newHandshakeState(protocolName, prologue, pskToken,
		false, ssB, XN, sBob, nil, nil, nil)
	require.Nil(t, err, "bob failed to create handshake state")

	// alice writes message, -> e
	ciphertextA, err := alice.WriteMessage(plaintext)
	require.Nil(t, err, "alice failed to write the first msg")
	require.Equal(t, 32+len(plaintext), len(ciphertextA),
		"ciphertextA should be a 32-byte public key + plaintext")
	require.Equal(t, 1, alice.patternIndex, "alice's pattern index should be 1")

	// bob reads message, -> e
	plaintextB, err := bob.ReadMessage(ciphertextA)
	require.Nil(t, err, "bob failed to read the first msg")
	require.Equal(t, plaintext, plaintextB,
		"bob failed to decrypt the first msg")
	require.Equal(t, alice.localEphemeral.PubKey().Bytes(),
		bob.remoteEphemeralPub.Bytes(), "bob should have alice's e")
	require.Equal(t, 1, bob.patternIndex, "bob's pattern index should be 1")

	// bob writes message, <- e, ee
	ciphertextB, err := bob.WriteMessage(plaintext)
	require.Nil(t, err, "bob failed to write the second msg")
	require.Equal(t, 32+16+len(plaintext), len(ciphertextB),
		"ciphertextB should be a 32-byte key + 16-byte AD + msg")
	require.Equal(t, 2, bob.patternIndex, "bob's pattern index should be 2")

	// alice reads message, <- e, ee
	plaintextA, err := alice.ReadMessage(ciphertextB)
	require.Nil(t, err, "alice failed to read the second msg")
	require.Equal(t, plaintext, plaintextA,
		"alice failed to decrypt the second msg")
	require.Equal(t, bob.localEphemeral.PubKey().Bytes(),
		alice.remoteEphemeralPub.Bytes(), "alice should have bob's e")
	require.Equal(t, 2, alice.patternIndex, "alice's pattern index should be 1")

	// alice writes message, ->s, se
	ciphertextA, err = alice.WriteMessage(plaintext)
	require.Nil(t, err, "alice failed to write the third msg")
	require.Equal(t, 32+16+len(plaintext), len(ciphertextB),
		"ciphertextA should be a 32-byte key + 16-byte AD + msg")
	require.Equal(t, 3, alice.patternIndex, "alice's pattern index should be 3")
	require.True(t, alice.Finished(), "alice should finish")

	// bob reads message, ->s, se
	plaintextB, err = bob.ReadMessage(ciphertextA)
	require.Nil(t, err, "bob failed to read the third msg")
	require.Equal(t, plaintext, plaintextB,
		"bob failed to decrypt the third msg")
	require.Equal(t, alice.localStatic.PubKey().Bytes(),
		bob.remoteStaticPub.Bytes(), "bob should have alice's s")
	require.Equal(t, 3, bob.patternIndex, "bob's pattern index should be 3")
	require.True(t, bob.Finished(), "bob should finish")

	// both alice and bob should have a pair of cipher state
	require.NotNil(t, alice.sendCipherState, "alice's sendCipherState")
	require.NotNil(t, alice.recvCipherState, "alice's recvCipherState")
	require.NotNil(t, bob.sendCipherState, "bob's sendCipherState")
	require.NotNil(t, bob.recvCipherState, "bob's recvCipherState")

	// the cipher state keys should match
	require.Equal(t, alice.sendCipherState.key, bob.recvCipherState.key,
		"alice's send not match bob's recv")
	require.Equal(t, bob.sendCipherState.key, alice.recvCipherState.key,
		"bob's send not match alice's recv")

	// test reset
	alice.Reset()
	require.Nil(t, alice.sendCipherState, "reset sendCipherState")
	require.Nil(t, alice.recvCipherState, "reset recvCipherState")
	bob.Reset()
	require.Nil(t, bob.sendCipherState, "reset sendCipherState")
	require.Nil(t, bob.recvCipherState, "reset recvCipherState")
}

func TestPskMode(t *testing.T) {}
