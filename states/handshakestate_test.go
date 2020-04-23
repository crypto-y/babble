package noise

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yyforyongyu/noise/pattern"
)

func TestInitializeHandshakeState(t *testing.T) {
	var protocolName = []byte("TestNoise")
	var longProtocolName = [1000]byte{}
	var prologue = []byte("YY")
	var wrongPsk = []byte{1, 2, 3}

	// cipher, _ := noiseCipher.FromString("ChaChaPoly")
	// hash, _ := noiseHash.FromString("BLAKE2s")
	// curve, _ := noiseCurve.FromString("secp256k1")

	// test long protocl name
	hs, err := newHandshakeState(longProtocolName[:], prologue,
		nil, true, nil, nil, nil, nil, nil, nil)
	require.Nil(t, hs, "no handshake state created")
	require.Equal(t, errProtocolNameInvalid, err,
		"wrong protocol name error should be returned")

	// test wrong psk size
	hs, err = newHandshakeState(protocolName, prologue, wrongPsk,
		true, nil, nil, nil, nil, nil, nil)
	require.Nil(t, hs, "no handshake state created")
	require.Equal(t, errInvalidPskSize, err,
		"invalid psk size error should be returned")

	// test nil symmetric state
	hs, err = newHandshakeState(protocolName, prologue, nil,
		true, nil, nil, nil, nil, nil, nil)
	require.Nil(t, hs, "no handshake state created")
	require.Equal(t, errMissingSymmetricState, err,
		"missing symmetric state error should be returned")

	// test nil handshake pattern
	cs := newCipherState(cipherG, nil)
	ss := newSymmetricState(cs, hashG, curveG)
	hs, err = newHandshakeState(protocolName, prologue, nil,
		true, ss, nil, nil, nil, nil, nil)
	require.Nil(t, hs, "no handshake state created")
	require.Equal(t, errMissingHandshakePattern, err,
		"missing handshake pattern error should be returned")

	// test initialize with error, this error is caused missing static public
	// key required in the KN handshake pattern.
	KN, _ := pattern.FromString("KN")
	hs, err = newHandshakeState(protocolName, prologue, nil,
		true, ss, KN, nil, nil, nil, nil)
	require.Nil(t, hs, "no handshake state created")
	require.NotNil(t, err, "an error should be returned from initialize")

	// test successfully created a handshake state
	NX, _ := pattern.FromString("NX")
	hs, err = newHandshakeState(protocolName, prologue, nil,
		true, ss, NX, nil, nil, nil, nil)
	require.Nil(t, err, "should return no error")
	require.NotNil(t, hs, "should return an hs instance")
}

func TestPskMode(t *testing.T) {}
