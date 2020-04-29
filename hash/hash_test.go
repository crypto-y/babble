package hash_test

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yyforyongyu/babble/hash"
)

func TestSetUp(t *testing.T) {
	// check supported hashes
	sha256, err := hash.FromString("SHA256")
	require.NotNil(t, sha256, "missing SHA256")
	require.Nil(t, err, "should return no error")

	sha512, err := hash.FromString("SHA512")
	require.NotNil(t, sha512, "missing SHA512")
	require.Nil(t, err, "should return no error")

	blake2s, err := hash.FromString("BLAKE2s")
	require.NotNil(t, blake2s, "missing BLAKE2s")
	require.Nil(t, err, "should return no error")

	blake2b, err := hash.FromString("BLAKE2b")
	require.NotNil(t, blake2b, "missing BLAKE2b")
	require.Nil(t, err, "should return no error")

	// check return empty
	yy, err := hash.FromString("yy")
	require.Nil(t, yy, "yy does not exist, yet")
	require.NotNil(t, err, "should return an error")

	require.Equal(t, len("BLAKE2b, BLAKE2s, SHA256, SHA512"),
		len(hash.SupportedHashes()),
		"hash BLAKE2b, BLAKE2s, SHA256, SHA512 should be returned")
}

func TestHash(t *testing.T) {
	message := []byte("noise")
	testParams := []struct {
		name     string
		hashLen  int
		blockLen int
		digest   string
	}{
		{"SHA256", 32, 64,
			"efe2a5c09e6d49d7eb735c9875f77404be5b887bb3f56378038968d4e3ff8198"},
		{"SHA512", 64, 128,
			"639536fe3055ba1c7e6a5fc53219f61cc6560b2045d36efa52da5e8547518" +
				"980545af2fa2db7a5b5c422d882d0bd8effb5b288b1d6fe0389253ec7" +
				"863bce113e"},
		{"BLAKE2s", 32, 64,
			"b21550f9332cb8f61ac92955e23447b18ad3452d71dd698f0190cb88718cf6da"},
		{"BLAKE2b", 64, 128,
			"d26cfaa295a94914bdedd0ceb2b955c80e4f1e7b33b37be4a16e9717021b76" +
				"091a12d9931e6de1bfe8844a41bcadc0bc0e0269886f0f11e83104a4f0" +
				"f92e20ad"},
	}

	for _, tt := range testParams {
		name := "test hash " + tt.name
		t.Run(name, func(t *testing.T) {
			h, err := hash.FromString(tt.name)
			hf := h.New()
			// no error
			require.Nil(t, err, "no error should be returned")
			// hash name
			require.Equal(t, tt.name, h.String(), "name mismatch")
			// block len
			require.Equal(t, tt.blockLen, h.BlockLen(), "block len mismatch")
			// hash len
			require.Equal(t, tt.hashLen, h.HashLen(), "hash len mismatch")
			// hash output
			_, _ = hf.Write(message)
			hashDigest := hex.EncodeToString(hf.Sum(nil))
			require.Equal(t, tt.digest, hashDigest, "hash digest is wrong")

			// test reset
			_, _ = hf.Write(message)
			hashDigest = hex.EncodeToString(hf.Sum(nil))
			require.NotEqual(t, tt.digest, hashDigest, "hash digest is wrong")
			h.Reset()
			_, _ = hf.Write(message)
			hashDigest = hex.EncodeToString(hf.Sum(nil))
			require.Equal(t, tt.digest, hashDigest, "hash digest is wrong")
		})
	}
}

func ExampleFromString() {
	// load hash sha256
	sha256, _ := hash.FromString("SHA256")
	fmt.Println(sha256)

	// load hash sha512
	sha512, _ := hash.FromString("SHA512")
	fmt.Println(sha512)

	// load hash blake2s
	blake2s, _ := hash.FromString("BLAKE2s")
	fmt.Println(blake2s)

	// load hash blake2b
	blake2b, _ := hash.FromString("BLAKE2b")
	fmt.Println(blake2b)
}
