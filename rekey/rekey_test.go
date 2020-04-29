package rekey

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	noiseCipher "github.com/yyforyongyu/babble/cipher"
)

func TestDefaultRekeyer(t *testing.T) {
	testInterval := uint64(1000)
	key := [CipherKeySize]byte{
		0xa8, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
		0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
		0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
		0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0x6b,
	}
	cipher, _ := noiseCipher.FromString("ChaChaPoly")
	cipher.InitCipher(key)
	rk := NewDefault(testInterval, cipher, true)

	newKey := rk.Rekey(nil)
	require.Equal(t, CipherKeySize, len(newKey), "key size not match")
	require.NotEqual(t, key, newKey, "key not changed")
	require.True(t, rk.ResetNonce(), "ResetNonce should be true")
	require.Equal(t, testInterval, rk.Interval(), "Interval not match")

	testParams := []struct {
		name        string
		nonce       uint64
		resetNonce  bool
		errExpected error
		need        bool
	}{
		{"no need and no error", 1, false, nil, false},
		{"no need and errCorruptedNonce",
			testInterval + uint64(1), true, errCorruptedNonce, false},
		{"need and no error", testInterval, false, nil, true},
	}

	for _, tt := range testParams {
		t.Run(tt.name, func(t *testing.T) {
			rk := NewDefault(testInterval, cipher, tt.resetNonce)
			need, err := rk.CheckRekey(tt.nonce)
			require.Equal(t, tt.errExpected, err, "error not match")
			require.Equal(t, tt.need, need, "need not match")
		})
	}
}

func ExampleNewDefault() {
	// Get the related cipher
	cipher, _ := noiseCipher.FromString("ChaChaPoly")

	// create a default rekeyer which rotates key every 1000 messages, and won't
	// touch the cipher's nonce.
	rekeyer1 := NewDefault(1000, cipher, false)
	fmt.Println(rekeyer1)

	// create a default rekeyer which rotates key every message, and won't touch
	// the cipher's nonce.
	rekeyer2 := NewDefault(1, cipher, false)
	fmt.Println(rekeyer2)

	// create a default rekeyer which rotates key every 10000 messages, and
	// reset the cipher's nonce.
	rekeyer3 := NewDefault(10000, cipher, true)
	fmt.Println(rekeyer3)
}
