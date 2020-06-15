package babble

import (
	"errors"
	"testing"

	"github.com/crypto-y/babble/cipher"
	noiseCipher "github.com/crypto-y/babble/cipher"
	"github.com/crypto-y/babble/dh"
	noiseCurve "github.com/crypto-y/babble/dh"
	noiseHash "github.com/crypto-y/babble/hash"
	"github.com/crypto-y/babble/pattern"
	"github.com/stretchr/testify/require"
)

func TestInitializeHandshakeState(t *testing.T) {
	var (
		cipherG, _ = noiseCipher.FromString("ChaChaPoly")
		hashG, _   = noiseHash.FromString("BLAKE2s")
		curveG, _  = noiseCurve.FromString("secp256k1")

		protocolName = []byte("TestNoise")
		prologue     = []byte("YY")
		psk          = []byte{
			0xa8, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0x6b,
		}
		pskToken = [][]byte{psk}

		csG = newCipherState(cipherG, nil)
		ssG = newSymmetricState(csG, hashG, curveG)
	)

	var longProtocolName = [1000]byte{}
	var wrongPsk = [][]byte{{1, 2, 3}}

	// test long protocl name
	hs, err := newHandshakeState(longProtocolName[:], prologue,
		nil, true, nil, nil, nil, nil, nil, nil, false)
	require.Nil(t, hs, "no handshake state created")
	require.Equal(t, errProtocolNameInvalid, err,
		"wrong protocol name error should be returned")

	// test nil symmetric state
	hs, err = newHandshakeState(protocolName, prologue, nil,
		true, nil, nil, nil, nil, nil, nil, false)
	require.Nil(t, hs, "no handshake state created")
	require.Equal(t, errMissingSymmetricState, err,
		"missing symmetric state error should be returned")

	// test nil handshake pattern
	hs, err = newHandshakeState(protocolName, prologue, nil,
		true, ssG, nil, nil, nil, nil, nil, false)
	require.Nil(t, hs, "no handshake state created")
	require.Equal(t, errMissingHandshakePattern, err,
		"missing handshake pattern error should be returned")

	// test initialize with error, this error is caused missing static public
	// key required in the KN handshake pattern.
	KN, _ := pattern.FromString("KN")
	hs, err = newHandshakeState(protocolName, prologue, nil,
		true, ssG, KN, nil, nil, nil, nil, false)
	require.Nil(t, hs, "no handshake state created")
	require.NotNil(t, err, "an error should be returned from initialize")

	// test missing psk token
	NXpsk0, _ := pattern.FromString("NXpsk0")
	hs, err = newHandshakeState(protocolName, prologue, nil,
		true, ssG, NXpsk0, nil, nil, nil, nil, false)
	require.Nil(t, hs, "no handshake state created")
	require.Equal(t, errMismatchedPsks(1, 0), err,
		"invalid psk size error should be returned")

	// test wrong psk size
	hs, err = newHandshakeState(protocolName, prologue, wrongPsk,
		true, ssG, NXpsk0, nil, nil, nil, nil, false)
	require.Nil(t, hs, "no handshake state created")
	require.Equal(t, errInvalidPskSize, err,
		"invalid psk size error should be returned")

	// test successfully created a handshake state
	hs, err = newHandshakeState(protocolName, prologue, pskToken,
		true, ssG, NXpsk0, nil, nil, nil, nil, false)
	require.Nil(t, err, "should return no error")
	require.NotNil(t, hs, "should return an hs instance")
	ck := hs.GetChainingKey()
	require.NotNil(t, ck, "ck is not nil")
	h := hs.GetDigest()
	require.NotNil(t, h, "digest is not nil")

	err = pattern.Register("YY", `
	-> e, s
	...
	-> ee
	`)
	require.Nil(t, err, "failed to create a new pattern")
	YY, _ := pattern.FromString("YYpsk0")

	// test no autopadding, will fail to create hs
	hs, err = newHandshakeState(protocolName, prologue, pskToken,
		true, ssG, YY, nil, nil, nil, nil, false)
	require.NotNil(t, err, "failed to create hs")

	// test autopadding s
	hs, err = newHandshakeState(protocolName, prologue, pskToken,
		true, ssG, YY, nil, nil, nil, nil, true)
	require.NoError(t, err, "failed to create hs")
	require.NotNil(t, hs.localStatic, "autopadding for s")
	require.NotNil(t, hs.localEphemeral, "autopadding for e")
}

func TestValidateKeys(t *testing.T) {
	var (
		cipherG, _ = noiseCipher.FromString("ChaChaPoly")
		hashG, _   = noiseHash.FromString("BLAKE2s")
		curveG, _  = noiseCurve.FromString("secp256k1")

		protocolName = []byte("TestNoise")
		prologue     = []byte("YY")
		psk          = []byte{
			0xa8, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0x6b,
		}
		pskToken = [][]byte{psk}

		csG        = newCipherState(cipherG, nil)
		ssG        = newSymmetricState(csG, hashG, curveG)
		remoteS, _ = curveG.GenerateKeyPair(nil)
		rs         = remoteS.PubKey()
	)

	testParams := []struct {
		name        string
		pattern     string
		initiator   bool
		e           dh.PrivateKey
		s           dh.PrivateKey
		re          dh.PublicKey
		rs          dh.PublicKey
		errExpected error
	}{
		// {"test e not empty", "N", true, e, s, re, rs,
		// 	errKeyNotEmpty("local ephemeral key")},
		// {"test re not empty", "NX", false, e, s, re, rs,
		// 	errKeyNotEmpty("remote ephemeral key")},
		{"test missing s", "XN", true, nil, nil, nil, rs,
			errMissingKey("local static key")},
		// {"test rs not empty", "XN", false, nil, s, nil, rs,
		// 	errKeyNotEmpty("remote static key")},
	}

	for _, tt := range testParams {
		t.Run(tt.name, func(t *testing.T) {
			p, err := pattern.FromString(tt.pattern)
			require.Nil(t, err, "error loading pattern")

			hs, err := newHandshakeState(protocolName, prologue, pskToken,
				tt.initiator, ssG, p, tt.s, tt.e, tt.rs, tt.re, false)
			require.Equal(t, tt.errExpected, err, "returned error not match")
			require.Nil(t, hs, "hs should be nil")
		})
	}

}

func TestProcessPreMessage(t *testing.T) {
	var (
		cipherG, _ = noiseCipher.FromString("ChaChaPoly")
		hashG, _   = noiseHash.FromString("BLAKE2s")
		curveG, _  = noiseCurve.FromString("secp256k1")

		protocolName = []byte("TestNoise")
		prologue     = []byte("YY")
		psk          = []byte{
			0xa8, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0x6b,
		}
		pskToken = [][]byte{psk}

		csG = newCipherState(cipherG, nil)
		ssG = newSymmetricState(csG, hashG, curveG)

		e, _       = curveG.GenerateKeyPair(nil)
		s, _       = curveG.GenerateKeyPair(nil)
		remoteE, _ = curveG.GenerateKeyPair(nil)
		remoteS, _ = curveG.GenerateKeyPair(nil)
		re         = remoteE.PubKey()
		rs         = remoteS.PubKey()
	)

	// create a test pattern
	err := pattern.Register("YY", `
	-> e, s
	...
	-> ee
	`)
	require.Nil(t, err, "failed to create a new pattern")

	YY, _ := pattern.FromString("YYpsk0")

	testParams := []struct {
		name        string
		initiator   bool
		e           dh.PrivateKey
		s           dh.PrivateKey
		re          dh.PublicKey
		rs          dh.PublicKey
		errExpected error
	}{
		{"missing local static key", true,
			e, nil, re, rs, errMissingKey("local static key")},
		{"missing remote static key", false,
			e, s, re, nil, errMissingKey("remote static key")},
		{"missing local ephemeral key", true,
			nil, s, re, rs, errMissingKey("local ephemeral key")},
		{"missing remote ephemeral key", false,
			e, s, nil, rs, errMissingKey("remote ephemeral key")},
		{"initiator success passed pre-message check", true,
			e, s, re, rs, nil},
		{"responder success passed pre-message check", false,
			e, s, re, rs, nil},
	}

	for _, tt := range testParams {
		t.Run(tt.name, func(t *testing.T) {
			hs, err := newHandshakeState(protocolName, prologue, pskToken,
				tt.initiator, ssG, YY, tt.s, tt.e, tt.rs, tt.re, false)
			if tt.errExpected != nil {
				require.Nil(t, hs, "handshake state should not be created")
			} else {
				require.NotNil(t, hs, "handshake state should be created")
			}

			require.Equal(t, tt.errExpected, err, "err returned not match")
		})
	}
}

func TestIncrementPatternIndexAndSplit(t *testing.T) {
	var (
		cipherG, _ = noiseCipher.FromString("ChaChaPoly")
		hashG, _   = noiseHash.FromString("BLAKE2s")
		curveG, _  = noiseCurve.FromString("secp256k1")

		protocolName = []byte("TestNoise")
		prologue     = []byte("YY")
		csG          = newCipherState(cipherG, nil)
		ssG          = newSymmetricState(csG, hashG, curveG)

		s, _ = curveG.GenerateKeyPair(nil)

		XN, _ = pattern.FromString("XN") // 3 lines of pattern
	)
	require := require.New(t)

	hs, err := newHandshakeState(protocolName, prologue, nil,
		true, ssG, XN, s, nil, nil, nil, false)
	require.Nil(err, "failed to create handshake state")
	require.Equal(0, hs.patternIndex, "pattern index is not 0")
	require.Nil(hs.SendCipherState, "no send cipher inited")
	require.Nil(hs.RecvCipherState, "no recv cipher inited")

	// increment once
	err = hs.incrementPatternIndexAndSplit()
	require.Nil(err, "failed to increment once")
	require.Equal(1, hs.patternIndex, "pattern index is not 1")
	require.Nil(hs.SendCipherState, "should have no send cipher inited")
	require.Nil(hs.RecvCipherState, "should have no recv cipher inited")

	// increment twice, should not be finished
	err = hs.incrementPatternIndexAndSplit()
	require.Nil(err, "failed to increment once")
	require.Equal(2, hs.patternIndex, "pattern index is not 2")
	require.Nil(hs.SendCipherState, "should have no send cipher inited")
	require.Nil(hs.RecvCipherState, "should have no recv cipher inited")

	// increment three times, should be finished
	err = hs.incrementPatternIndexAndSplit()
	require.Nil(err, "failed to increment once")
	require.Equal(3, hs.patternIndex, "pattern index is not 3")
	require.NotNil(hs.SendCipherState, "should have send cipher inited")
	require.NotNil(hs.RecvCipherState, "should have recv cipher inited")

	// make an overflow error
	err = hs.incrementPatternIndexAndSplit()
	require.Equal(errPatternIndexOverflow, err,
		"should return an overflow error")
	require.Equal(4, hs.patternIndex, "pattern index is not 1")

	// make an invalid chain key error
	hs, _ = newHandshakeState(protocolName, prologue, nil,
		true, ssG, XN, s, nil, nil, nil, false)
	hs.ss.chainingKey = nil
	// increase twice to trigger the error
	hs.incrementPatternIndexAndSplit()
	hs.incrementPatternIndexAndSplit()
	err = hs.incrementPatternIndexAndSplit()
	require.Equal(errInvalidChainingKey, err,
		"should return an invalid chain size error")
	require.Equal(3, hs.patternIndex, "pattern index is not 1")
	require.Nil(hs.SendCipherState, "should have no send cipher inited")
	require.Nil(hs.RecvCipherState, "should have no recv cipher inited")

}

func TestProcessReadTokenE(t *testing.T) {
	var (
		cipherG, _ = noiseCipher.FromString("ChaChaPoly")
		hashG, _   = noiseHash.FromString("BLAKE2s")
		curveG, _  = noiseCurve.FromString("secp256k1")

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
		protocolName = []byte("TestNoise")
		prologue     = []byte("YY")
		psk          = []byte{
			0xa8, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0x6b,
		}
		pskToken = [][]byte{psk}

		csG = newCipherState(cipherG, nil)
		ssG = newSymmetricState(csG, hashG, curveG)

		s, _       = curveG.GenerateKeyPair(nil)
		remoteE, _ = curveG.GenerateKeyPair(nil)
		remoteS, _ = curveG.GenerateKeyPair(nil)
		re         = remoteE.PubKey()
		rs         = remoteS.PubKey()

		XNpsk0, _ = pattern.FromString("XNpsk0") // 3 lines of pattern
	)

	// test when re is not empty
	hs, err := newHandshakeState(protocolName, prologue, pskToken,
		true, ssG, XNpsk0, s, nil, rs, nil, false)
	require.Nil(t, err, "failed to create handshake state")
	hs.remoteEphemeralPub = re
	p, err := hs.readTokenE(nil)
	require.Nil(t, p, "no payload should be returned")
	require.Equal(t, errKeyNotEmpty("remote ephemeral key"), err,
		"should return key not empty error")

	// test invalid payload
	hs, err = newHandshakeState(protocolName, prologue, pskToken,
		true, ssG, XNpsk0, s, nil, rs, nil, false)
	p, err = hs.readTokenE(nil)
	require.Nil(t, p, "no payload should be returned")
	require.Equal(t, errInvalidPayload, err, "should return errInvalidPayload")

	// test load wrong pub key
	payload := append(key[:], byte(0))
	p, err = hs.readTokenE(payload)
	require.Equal(t, "invalid magic in compressed pubkey string: 168",
		err.Error(), "should return an error")
	require.Nil(t, p, "no payload should be returned")

	// test successfully read
	p, err = hs.readTokenE(pubBitcoin[:])
	require.Nil(t, err, "should return no error")
	require.Equal(t, 0, len(p), "should return zero-length payload")
	require.Equal(t, pubBitcoin[:], hs.remoteEphemeralPub.Bytes(),
		"re not match")
}

func TestProcessReadTokenS(t *testing.T) {
	var (
		cipherG, _ = noiseCipher.FromString("ChaChaPoly")
		hashG, _   = noiseHash.FromString("BLAKE2s")
		curveG, _  = noiseCurve.FromString("secp256k1")

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

		protocolName = []byte("TestNoise")
		prologue     = []byte("YY")
		psk          = []byte{
			0xa8, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0x6b,
		}
		pskToken = [][]byte{psk}

		csG       = newCipherState(cipherG, nil)
		ssG       = newSymmetricState(csG, hashG, curveG)
		s, _      = curveG.GenerateKeyPair(nil)
		XN, _     = pattern.FromString("XN")     // 3 lines of pattern
		XNpsk0, _ = pattern.FromString("XNpsk0") // 3 lines of pattern
	)

	// test invalid payload
	hs, err := newHandshakeState(protocolName, prologue, pskToken,
		true, ssG, XNpsk0, s, nil, nil, nil, false)
	// hs.ss.InitializeSymmetric(protocolName)
	p, err := hs.readTokenS(nil)
	require.Nil(t, p, "no payload should be returned")
	require.Equal(t, errInvalidPayload, err, "should return errInvalidPayload")

	// test load wrong pub key
	payload := append(key[:], byte(0))
	p, err = hs.readTokenS(payload)
	require.Nil(t, p, "no payload should be returned")
	require.Equal(t, "invalid magic in compressed pubkey string: 168",
		err.Error(), "should return an error")

	// test successfully read
	p, err = hs.readTokenS(pubBitcoin[:])
	require.Nil(t, err, "should return no error")
	require.Equal(t, 0, len(p), "should return zero-length payload")
	require.Equal(t, pubBitcoin[:], hs.remoteStaticPub.Bytes(), "rs not match")

	// test failed to decrypt
	hs, err = newHandshakeState(protocolName, prologue, pskToken,
		true, ssG, XN, s, nil, nil, nil, false)
	err = hs.ss.cs.initializeKey(key)
	require.NoError(t, err, "failed to initilize key")
	payload = append(key[:], pubBitcoin[:]...)
	p, err = hs.readTokenS(payload)
	require.EqualError(t, err,
		"chacha20poly1305: message authentication failed",
		"should return an error")
	require.Nil(t, p, "no payload should be returned")

}

func TestProcessTokenPsk(t *testing.T) {
	var (
		cipherG, _ = noiseCipher.FromString("ChaChaPoly")
		hashG, _   = noiseHash.FromString("BLAKE2s")
		curveG, _  = noiseCurve.FromString("secp256k1")

		protocolName = []byte("TestNoise")
		prologue     = []byte("YY")
		psk          = []byte{
			0xa8, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0x6b,
		}
		pskToken = [][]byte{psk}

		csG       = newCipherState(cipherG, nil)
		ssG       = newSymmetricState(csG, hashG, curveG)
		s, _      = curveG.GenerateKeyPair(nil)
		XNpsk0, _ = pattern.FromString("XNpsk0") // 3 lines of pattern
	)

	// test success
	hs, err := newHandshakeState(protocolName, prologue, pskToken,
		true, ssG, XNpsk0, s, nil, nil, nil, false)
	require.Nil(t, err, "failed to create handshake state")
	err = hs.processTokenPsk()
	require.Nil(t, err, "should return no error")

	// calling again will cause an overflow error
	err = hs.processTokenPsk()
	require.Equal(t, errPskIndexOverflow, err, "should return overflow error")

	// test return an error
	hs.pskIndex = 0
	hs.ss.chainingKey = nil
	err = hs.processTokenPsk()
	require.Equal(t, errInvalidChainingKey, err,
		"should return errInvalidChainingKey")
}

func TestProcessTokenDH(t *testing.T) {
	var (
		cipherG, _ = noiseCipher.FromString("ChaChaPoly")
		hashG, _   = noiseHash.FromString("BLAKE2s")
		curveG, _  = noiseCurve.FromString("secp256k1")
		curveA, _  = noiseCurve.FromString("25519")

		protocolName = []byte("TestNoise")
		prologue     = []byte("YY")
		psk          = []byte{
			0xa8, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0x6b,
		}
		pskToken = [][]byte{psk}

		csG = newCipherState(cipherG, nil)
		ssG = newSymmetricState(csG, hashG, curveG)

		e, _       = curveG.GenerateKeyPair(nil)
		s, _       = curveG.GenerateKeyPair(nil)
		remoteE, _ = curveG.GenerateKeyPair(nil)
		remoteS, _ = curveG.GenerateKeyPair(nil)
		re         = remoteE.PubKey()
		rs         = remoteS.PubKey()

		// create a different type of key based on a different curve
		wrongRemoteE, _ = curveA.GenerateKeyPair(nil)
		wrongRe         = wrongRemoteE.PubKey()

		XN, _ = pattern.FromString("XN") // 3 lines of pattern
	)

	testParams := []struct {
		name        string
		token       pattern.Token
		initiator   bool
		e           dh.PrivateKey
		re          dh.PublicKey
		rs          dh.PublicKey
		errExpected error
	}{
		{"initiator successfully process ee",
			pattern.TokenEe, true, e, re, rs, nil},
		{"initiator successfully process es",
			pattern.TokenEs, true, e, re, rs, nil},
		{"initiator successfully process se",
			pattern.TokenSe, true, e, re, rs, nil},
		{"initiator successfully process ss",
			pattern.TokenSs, true, e, re, rs, nil},
		{"responder successfully process ee",
			pattern.TokenEe, false, e, re, nil, nil},
		{"responder successfully process es",
			pattern.TokenEs, false, e, re, nil, nil},
		{"responder successfully process se",
			pattern.TokenSe, false, e, re, rs, nil},
		{"responder successfully process ss",
			pattern.TokenSs, false, e, re, rs, nil},
		{"failed when missing local key",
			pattern.TokenEe, true, nil, re, rs,
			errMissingKey("missing key when performing DH")},
		{"failed when missing remote key",
			pattern.TokenEe, true, e, nil, rs,
			errMissingKey("missing key when performing DH")},
		{"failed when performing on a wrong pubkey in DH",
			pattern.TokenEe, true, e, wrongRe, rs,
			errors.New("public key is wrong: want 33 bytes, got 32 bytes")},
		{"failed to process on a wrong token",
			pattern.TokenS, true, e, re, rs,
			errInvalidDHToken(pattern.TokenS)},
	}

	for _, tt := range testParams {
		t.Run(tt.name, func(t *testing.T) {

			// test setup
			hs, err := newHandshakeState(protocolName, prologue, pskToken,
				tt.initiator, ssG, XN, s, nil, nil, nil, false)
			require.Nil(t, err, "failed to create handshake state")

			oldCk := hs.ss.chainingKey
			require.Equal(t, ZEROS, hs.ss.cs.key, "cipher key should be zeros")

			hs.remoteEphemeralPub = tt.re
			hs.localEphemeral = tt.e
			hs.remoteStaticPub = tt.rs
			err = hs.processTokenDH(tt.token)
			require.Equal(t, tt.errExpected, err, "expected error not returned")

			// check ck and cipher key
			if tt.errExpected != nil {
				require.Equal(t, oldCk, hs.ss.chainingKey,
					"ck should not changed")
				require.Equal(t, ZEROS, hs.ss.cs.key,
					"cipher key should be zeros")
			} else {
				require.NotEqual(t, oldCk, hs.ss.chainingKey,
					"ck has not changed")
				require.NotEqual(t, ZEROS, hs.ss.cs.key,
					"cipher key should be created")
			}
		})
	}

}

func TestProcessReadToken(t *testing.T) {
	var (
		cipherG, _ = noiseCipher.FromString("ChaChaPoly")
		hashG, _   = noiseHash.FromString("BLAKE2s")
		curveG, _  = noiseCurve.FromString("secp256k1")

		protocolName = []byte("TestNoise")
		prologue     = []byte("YY")
		psk          = []byte{
			0xa8, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0x6b,
		}
		pskToken = [][]byte{psk}

		csG = newCipherState(cipherG, nil)
		ssG = newSymmetricState(csG, hashG, curveG)

		s, _       = curveG.GenerateKeyPair(nil)
		remoteE, _ = curveG.GenerateKeyPair(nil)
		remoteS, _ = curveG.GenerateKeyPair(nil)
		re         = remoteE.PubKey()
		rs         = remoteS.PubKey()

		XN, _ = pattern.FromString("XN") // 3 lines of pattern
	)

	testParams := []struct {
		name            string
		token           pattern.Token
		payload         []byte
		re              dh.PublicKey
		rs              dh.PublicKey
		errExpected     error
		payloadExpected []byte
	}{
		{"successfully process e", pattern.TokenE, re.Bytes(), nil, nil,
			nil, []byte{}},
		{"successfully process s", pattern.TokenS, rs.Bytes(), nil, nil,
			nil, []byte{}},
		{"error process s", pattern.TokenS, protocolName, nil, rs,
			errInvalidPayload, nil},
		{"successfully process psk", pattern.TokenPsk, rs.Bytes(), nil, nil,
			nil, rs.Bytes()},
		{"successfully process dh", pattern.TokenSs, rs.Bytes(), nil, rs,
			nil, rs.Bytes()},
		{"error process dh", pattern.TokenSs, rs.Bytes(), nil, nil,
			errMissingKey("missing key when performing DH"), nil},
	}

	for _, tt := range testParams {
		t.Run(tt.name, func(t *testing.T) {
			// test setup
			hs, err := newHandshakeState(protocolName, prologue, pskToken,
				true, ssG, XN, s, nil, tt.rs, nil, false)
			require.Nil(t, err, "failed to create handshake state")

			hs.remoteEphemeralPub = tt.re
			payload, err := hs.processReadToken(tt.token, tt.payload)
			require.Equal(t, tt.errExpected, err, "expected error not returned")
			require.Equal(t, tt.payloadExpected, payload,
				"expected payload not returned")
		})
	}

	// test an edge case for psk
	hs, err := newHandshakeState(protocolName, prologue, pskToken,
		true, ssG, XN, s, nil, rs, nil, false)
	require.Nil(t, err, "failed to create handshake state")
	hs.pskIndex = 1
	payload, err := hs.processReadToken(pattern.TokenPsk, nil)
	require.Nil(t, payload, "should return nil payload")
	require.Equal(t, errPskIndexOverflow, err, "should return overflow error")
}

func TestProcessWriteTokenE(t *testing.T) {
	var (
		cipherG, _ = noiseCipher.FromString("ChaChaPoly")
		hashG, _   = noiseHash.FromString("BLAKE2s")
		curveG, _  = noiseCurve.FromString("secp256k1")

		protocolName = []byte("TestNoise")
		prologue     = []byte("YY")
		psk          = []byte{
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
		pskToken = [][]byte{psk}

		csG = newCipherState(cipherG, nil)
		ssG = newSymmetricState(csG, hashG, curveG)

		s, _       = curveG.GenerateKeyPair(nil)
		remoteS, _ = curveG.GenerateKeyPair(nil)
		rs         = remoteS.PubKey()

		XNpsk0, _ = pattern.FromString("XNpsk0") // 3 lines of pattern
	)

	payload := []byte{}

	// test success
	hs, err := newHandshakeState(protocolName, prologue, pskToken,
		true, ssG, XNpsk0, s, nil, rs, nil, false)
	require.Nil(t, err, "failed to create handshake state")

	oldDigest := hs.ss.digest
	p, err := hs.writeTokenE(payload)
	require.Nil(t, err, "should have no error")
	require.Equal(t, len(pubBitcoin), len(p), "payload should be 33-byte")
	require.NotEqual(t, oldDigest, hs.ss.digest, "digest should change")

}

func TestProcessWriteTokenS(t *testing.T) {
	var (
		cipherG, _ = noiseCipher.FromString("ChaChaPoly")
		hashG, _   = noiseHash.FromString("BLAKE2s")
		curveG, _  = noiseCurve.FromString("secp256k1")

		protocolName = []byte("TestNoise")
		prologue     = []byte("YY")
		psk          = []byte{
			0xa8, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0x6b,
		}
		key = [CipherKeySize]byte{
			0xa8, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0x6b,
		}

		pskToken = [][]byte{psk}
		maxNonce = cipher.MaxNonce

		csG  = newCipherState(cipherG, nil)
		ssG  = newSymmetricState(csG, hashG, curveG)
		s, _ = curveG.GenerateKeyPair(nil)

		XNpsk0, _ = pattern.FromString("XNpsk0") // 3 lines of pattern
	)

	payload := []byte{}
	hs, err := newHandshakeState(protocolName, prologue, pskToken,
		true, ssG, XNpsk0, s, nil, nil, nil, false)
	require.Nil(t, err, "failed to create handshake state")

	// test missing key
	hs.localStatic = nil
	p, err := hs.writeTokenS(payload)
	require.Equal(t, errMissingKey("local static key"), err,
		"should have an error")
	require.Nil(t, p, "should return no payload")

	// test success
	oldDigest := hs.ss.digest
	hs.localStatic = s
	p, err = hs.writeTokenS(payload)
	require.Nil(t, err, "should have no error")
	require.False(t, hs.ss.cs.hasKey(), "should have no key")
	require.Equal(t, s.PubKey().Bytes(), p,
		"payload should local static public key")
	require.NotEqual(t, oldDigest, hs.ss.digest, "digest should change")

	// test an edge case
	hs.ss.cs.key = key
	hs.ss.cs.nonce = maxNonce
	p, err = hs.writeTokenS(payload)
	require.Equal(t, cipher.ErrNonceOverflow, err, "should have an error")
	require.Nil(t, p, "payload should be nil")

}

func TestProcessWriteToken(t *testing.T) {
	var (
		cipherG, _ = noiseCipher.FromString("ChaChaPoly")
		hashG, _   = noiseHash.FromString("BLAKE2s")
		curveG, _  = noiseCurve.FromString("secp256k1")

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

		csG = newCipherState(cipherG, nil)
		ssG = newSymmetricState(csG, hashG, curveG)

		s, _       = curveG.GenerateKeyPair(nil)
		remoteS, _ = curveG.GenerateKeyPair(nil)
		rs         = remoteS.PubKey()

		XNpsk0, _ = pattern.FromString("XNpsk0") // 3 lines of pattern
	)

	payload := []byte{}

	// test error when processing token e
	hs, err := newHandshakeState(protocolName, prologue, pskToken,
		true, ssG, XNpsk0, s, nil, rs, nil, false)
	require.Nil(t, err, "failed to create handshake state")

	// test error when processing token s
	hs.ss.cs.key = key
	hs.ss.cs.nonce = maxNonce
	p, err := hs.processWriteToken(pattern.TokenS, payload)
	require.Nil(t, p, "should return no payload")
	require.Equal(t, cipher.ErrNonceOverflow, err, "error returned not match")

	// test error when processing token psk
	hs.pskIndex = 1
	p, err = hs.processWriteToken(pattern.TokenPsk, payload)
	require.Nil(t, p, "should return no payload")
	require.Equal(t, errPskIndexOverflow, err, "error returned not match")

	// test error when processing DH
	hs.localEphemeral = nil
	p, err = hs.processWriteToken(pattern.TokenEe, payload)
	require.Nil(t, p, "should return no payload")
	require.Equal(t, errMissingKey("missing key when performing DH"), err,
		"error returned not match")

	// test process the line "e, s"
	hs, err = newHandshakeState(protocolName, prologue, pskToken,
		true, ssG, XNpsk0, s, nil, rs, nil, false)
	p, err = hs.processWriteToken(pattern.TokenE, payload)
	require.Nil(t, err, "should return no error")
	require.Equal(t, len(pubBitcoin), len(p),
		"returned payload length not match")

	newP, err := hs.processWriteToken(pattern.TokenS, p)
	dhlen := hs.ss.curve.Size()
	adlen := hs.ss.cs.cipher.Cipher().Overhead()

	require.Nil(t, err, "should return no error")
	require.Equal(t, dhlen*2+adlen, len(newP),
		"returned payload length not match")

}

func TestReadMessageErrors(t *testing.T) {
	var (
		cipherG, _ = noiseCipher.FromString("ChaChaPoly")
		hashG, _   = noiseHash.FromString("BLAKE2s")
		curveG, _  = noiseCurve.FromString("secp256k1")

		protocolName = []byte("TestNoise")
		prologue     = []byte("YY")
		psk          = []byte{
			0xa8, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0x6b,
		}
		pskToken = [][]byte{psk}

		csG = newCipherState(cipherG, nil)
		ssG = newSymmetricState(csG, hashG, curveG)

		e, _       = curveG.GenerateKeyPair(nil)
		s, _       = curveG.GenerateKeyPair(nil)
		remoteE, _ = curveG.GenerateKeyPair(nil)
		remoteS, _ = curveG.GenerateKeyPair(nil)
		re         = remoteE.PubKey()
		rs         = remoteS.PubKey()

		XNpsk0, _ = pattern.FromString("XNpsk0") // 3 lines of pattern
	)

	// -> e
	// <- e, ee
	// -> s, se
	hs, _ := newHandshakeState(protocolName, prologue, pskToken,
		true, ssG, XNpsk0, s, nil, rs, nil, false)

	// test message too big
	bigMessage := [maxMessageSize + 1]byte{}
	p, err := hs.ReadMessage(bigMessage[:])
	require.Equal(t, errMessageOverflow, err,
		"should return message too big error")
	require.Nil(t, p, "should return no plaintext")

	message := re.Bytes()

	// test wrong direction error
	p, err = hs.ReadMessage(message)
	require.Equal(t,
		errInvalidDirection("ReadMessage: ", true, pattern.TokenInitiator),
		err, "should return direction wrong error")
	require.Nil(t, p, "should return no plaintext")

	// test pattern index error
	hs.patternIndex = 3
	p, err = hs.ReadMessage(message)
	require.Equal(t, errPatternIndexOverflow, err,
		"should return pattern index overflow error")
	require.Nil(t, p, "should return no plaintext")

	// jump to line 2 and continue the test
	hs.patternIndex = 1

	// test re is not empty error
	hs.remoteEphemeralPub = re
	p, err = hs.ReadMessage(message)
	require.Equal(t, errKeyNotEmpty("remote ephemeral key"), err,
		"should return key not empty error")
	require.Nil(t, p, "should return no plaintext")

	// test failed to decrypt
	hs.localEphemeral = e
	hs.remoteEphemeralPub = nil
	p, err = hs.ReadMessage(message)
	require.Equal(t, "chacha20poly1305: message authentication failed",
		err.Error(), "should return MAC failed error")
	require.Nil(t, p, "should return no plaintext")
}

func TestWriteMessageErrors(t *testing.T) {
	var (
		cipherG, _ = noiseCipher.FromString("ChaChaPoly")
		hashG, _   = noiseHash.FromString("BLAKE2s")
		curveG, _  = noiseCurve.FromString("secp256k1")

		key = [CipherKeySize]byte{
			0xa8, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0x6b,
		}
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

		csG  = newCipherState(cipherG, nil)
		ssG  = newSymmetricState(csG, hashG, curveG)
		s, _ = curveG.GenerateKeyPair(nil)
	)

	// create a test pattern with nonsense
	err := pattern.Register("YYY", `
	-> s
	<- s
	-> s
	`)
	require.Nil(t, err, "failed to create a new pattern")
	YYYpsk0, _ := pattern.FromString("YYYpsk0")

	hs, err := newHandshakeState(protocolName, prologue, pskToken,
		true, ssG, YYYpsk0, s, nil, nil, nil, false)
	require.Nil(t, err, "should return no error")

	// test message too big
	bigPayload := [maxMessageSize + 1]byte{}
	c, err := hs.WriteMessage(bigPayload[:])
	require.Equal(t, errMessageOverflow, err,
		"should return message too big error")
	require.Nil(t, c, "should return no ciphertext")

	payload := []byte{}

	// test wrong direction error
	hs.patternIndex = 1
	c, err = hs.WriteMessage(payload)
	require.Equal(t,
		errInvalidDirection("WriteMessage: ", true, pattern.TokenResponder),
		err, "should return direction wrong error")
	require.Nil(t, c, "should return no ciphertext")

	// test pattern index error
	hs.patternIndex = 3
	c, err = hs.WriteMessage(payload)
	require.Equal(t, errPatternIndexOverflow, err,
		"should return pattern index overflow error")
	require.Nil(t, c, "should return no ciphertext")

	// reset to line 1 and continue the test
	hs.patternIndex = 0

	// test encryt with error
	hs.localEphemeral = nil
	hs.ss.cs.key = key
	hs.ss.cs.cipher = nil
	hs.ss.cs.nonce = maxNonce
	hs.patternIndex = 2
	hs.localStatic = s
	c, err = hs.WriteMessage(payload)
	require.Equal(t, errCipherNotInitialized, err, "should have an error")
	require.Nil(t, c, "should return no ciphertext")
}

func TestReset(t *testing.T) {
	var (
		cipherG, _ = noiseCipher.FromString("ChaChaPoly")
		hashG, _   = noiseHash.FromString("BLAKE2s")
		curveG, _  = noiseCurve.FromString("secp256k1")

		protocolName = []byte("TestNoise")
		prologue     = []byte("YY")
		psk          = []byte{
			0xa8, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0x6b,
		}
		pskToken = [][]byte{psk}

		csG = newCipherState(cipherG, nil)
		ssG = newSymmetricState(csG, hashG, curveG)

		s, _       = curveG.GenerateKeyPair(nil)
		remoteS, _ = curveG.GenerateKeyPair(nil)
		rs         = remoteS.PubKey()

		XNpsk0, _ = pattern.FromString("XNpsk0") // 3 lines of pattern
	)

	hs, _ := newHandshakeState(protocolName, prologue, pskToken,
		true, ssG, XNpsk0, s, nil, rs, nil, false)

	hs.Reset()
	require.NotNil(t, hs.psks, "should not touch psks")
	require.Equal(t, 0, hs.patternIndex, "reset patternIndex")
	require.NotNil(t, hs.hp, "should not touch hp")
	require.Nil(t, hs.localStatic, "reset localStatic")
	require.Nil(t, hs.remoteStaticPub, "reset remoteStaticPub")
	require.Nil(t, hs.localEphemeral, "reset localEphemeral")
	require.Nil(t, hs.remoteEphemeralPub, "reset remoteEphemeralPub")
	require.Nil(t, hs.ss, "reset ss")
	require.Nil(t, hs.SendCipherState, "reset SendCipherState")
	require.Nil(t, hs.RecvCipherState, "reset RecvCipherState")
}

func TestHandshakeState(t *testing.T) {
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

		protocolName = []byte("TestNoise")
		prologue     = []byte("YY")
		psk          = []byte{
			0xa8, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0x6b,
		}
		pskToken = [][]byte{psk}

		XN, _ = pattern.FromString("XN") // 3 lines of pattern
	)

	// Pattern used for testing,
	// -> e
	// <- e, ee
	// -> s, se
	plaintext := []byte("crypto-y")
	sAlice, _ := curveA.GenerateKeyPair(nil)
	sBob, _ := curveB.GenerateKeyPair(nil)

	alice, err := newHandshakeState(protocolName, prologue, pskToken,
		true, ssA, XN, sAlice, nil, nil, nil, false)
	require.Nil(t, err, "alice failed to create handshake state")

	bob, err := newHandshakeState(protocolName, prologue, pskToken,
		false, ssB, XN, sBob, nil, nil, nil, false)
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
	require.NotNil(t, alice.SendCipherState, "alice's SendCipherState")
	require.NotNil(t, alice.RecvCipherState, "alice's RecvCipherState")
	require.NotNil(t, bob.SendCipherState, "bob's SendCipherState")
	require.NotNil(t, bob.RecvCipherState, "bob's RecvCipherState")

	// the cipher state keys should match
	require.Equal(t, alice.SendCipherState.key, bob.RecvCipherState.key,
		"alice's send not match bob's recv")
	require.Equal(t, bob.SendCipherState.key, alice.RecvCipherState.key,
		"bob's send not match alice's recv")

	// test getinfo
	// TODO: test the info format
	_, err = alice.GetInfo()
	require.Nil(t, err, "GetInfo failed")
	_, err = bob.GetInfo()
	require.Nil(t, err, "GetInfo failed")

	// test reset
	alice.Reset()
	require.Nil(t, alice.SendCipherState, "reset SendCipherState")
	require.Nil(t, alice.RecvCipherState, "reset RecvCipherState")
	bob.Reset()
	require.Nil(t, bob.SendCipherState, "reset SendCipherState")
	require.Nil(t, bob.RecvCipherState, "reset RecvCipherState")
}
