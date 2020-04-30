package babble

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yyforyongyu/babble/vectors"
)

const filepath = "./vectors/vectors.txt"

func TestVectors(t *testing.T) {
	require := require.New(t)
	// load test file
	data, err := ioutil.ReadFile(filepath)
	require.NoError(err, "failed to load test file")

	// create json
	var vectorsFile vectors.File
	err = json.Unmarshal(data, &vectorsFile)
	require.NoError(err, "failed to unmarshal data")

	for i, v := range vectorsFile.Vectors[:] {
		t.Run(strconv.Itoa(i)+" - "+v.ProtocolName, func(t *testing.T) {
			testVector(t, &v)
		})
	}
}

func testVector(t *testing.T, v *vectors.Vector) {
	require := require.New(t)
	aliceCfg, bobCfg := createConfigFromVector(t, v)

	alice, err := NewProtocolWithConfig(aliceCfg)
	require.NoError(err, "failed to create alice's handshake state")
	defer alice.reset()

	bob, err := NewProtocolWithConfig(bobCfg)
	require.NoError(err, "failed to create bob's handshake state")
	defer bob.reset()

	testMessages(t, alice, bob, v)
}

func testMessages(t *testing.T, alice, bob *HandshakeState,
	v *vectors.Vector) {
	require := require.New(t)

	n := len(alice.hp.MessagePattern)
	for i, msg := range v.Messages[:n] {
		// the even msg must be written by an initiator, and be read by a
		// responder.
		if i%2 == 0 {
			ciphertext, err := alice.WriteMessage(msg.Payload)
			require.NoError(err, "failed to write message")
			require.Equal([]byte(msg.Ciphertext), ciphertext,
				"failed to encrypt %v", i)

			plaintext, err := bob.ReadMessage(msg.Ciphertext)
			require.NoError(err, "failed to read message")
			require.Equal([]byte(msg.Payload), plaintext,
				"failed to decrypt %v", i)
		} else {
			ciphertext, err := bob.WriteMessage(msg.Payload)
			require.NoError(err, "failed to write message")
			require.Equal([]byte(msg.Ciphertext), ciphertext,
				"failed to encrypt %v", i)

			plaintext, err := alice.ReadMessage(msg.Ciphertext)
			require.NoError(err, "failed to read message")
			require.Equal([]byte(msg.Payload), plaintext,
				"failed to decrypt %v", i)
		}
	}

	require.True(alice.Finished(), "must be finished at the end")
	require.True(bob.Finished(), "must be finished at the end")

	if v.HandshakeHash != nil {
		require.EqualValues([]byte(v.HandshakeHash), alice.GetDigest(),
			"alice handshake digest not match")
		require.EqualValues([]byte(v.HandshakeHash), bob.GetDigest(),
			"bob handshake digest not match")
	}

	for i, msg := range v.Messages[n:] {
		// test cipher state
		sc := alice.SendCipherState
		rc := bob.RecvCipherState

		if (i+n)%2 != 0 {
			sc = bob.SendCipherState
			rc = alice.RecvCipherState

			// if the pattern is one-way, ignore the second cipher state
			if sc == nil {
				sc = bob.RecvCipherState
				rc = alice.SendCipherState
			}
		}
		defer sc.reset()
		defer rc.reset()

		require.Equal(sc.key, rc.key, "send and recv keys should match")

		ciphertext, err := sc.EncryptWithAd(
			nil, msg.Payload)
		require.NoError(err,
			"Transport: send failed to encrypt %v", i+n)
		require.Equal([]byte(msg.Ciphertext), ciphertext,
			"Transport: send - mismatched encrypt %v", i+n)

		plaintext, err := rc.DecryptWithAd(
			nil, msg.Ciphertext)
		require.NoError(err, "Transport: recv failed to decrypt")
		require.Equal([]byte(msg.Payload), plaintext,
			"Transport: recv - mismatched decrypt %v", i+n)

	}
}

func createConfigFromVector(t *testing.T, v *vectors.Vector) (
	*ProtocolConfig, *ProtocolConfig) {
	alice := &ProtocolConfig{
		Name:               v.ProtocolName,
		Initiator:          true,
		LocalStaticPriv:    v.InitStatic,
		LocalEphemeralPriv: v.InitEphemeral,
		RemoteStaticPub:    v.InitRemoteStatic,
		Prologue:           fmt.Sprintf("%s", v.InitPrologue),
	}

	for _, psk := range v.InitPsks {
		alice.Psks = append(alice.Psks, psk)
	}

	bob := &ProtocolConfig{
		Name:               v.ProtocolName,
		Initiator:          false,
		LocalStaticPriv:    v.RespStatic,
		LocalEphemeralPriv: v.RespEphemeral,
		RemoteStaticPub:    v.RespRemoteStatic,
		Prologue:           fmt.Sprintf("%s", v.RespPrologue),
	}

	for _, psk := range v.RespPsks {
		bob.Psks = append(bob.Psks, psk)
	}

	return alice, bob
}
