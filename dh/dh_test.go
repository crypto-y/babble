package dh_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yyforyongyu/noise/dh"
)

var (
	invalidPub = []byte{byte(1)}
)

type invalid struct {
	raw [1]byte
}

func (i *invalid) Bytes() []byte {
	return i.raw[:]
}

func (i *invalid) Hex() string {
	return ""
}

func TestSetUp(t *testing.T) {
	// check supported curves
	require.NotNil(t, dh.FromString("25519"), "missing 25519")
	require.NotNil(t, dh.FromString("448"), "missing 448")
	require.NotNil(t, dh.FromString("secp256k1"), "missing secp256k1")

	// check return empty
	require.Nil(t, dh.FromString("yy"), "yy does not exist, yet")

	require.Equal(t, len("25519, 448, secp256k1"), len(dh.SupportedCurves()),
		"curve 25519, 448 and secp256k1 should be returned")
}

func ExampleFromString() {
	// use the curve25519
	x25519 := dh.FromString("25519")
	fmt.Println(x25519)

	// use the curve448
	x448 := dh.FromString("448")
	fmt.Println(x448)

	// use the secp256k1
	secp256k1 := dh.FromString("secp256k1")
	fmt.Println(secp256k1)
}
