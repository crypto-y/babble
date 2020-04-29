package dh_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yyforyongyu/babble/dh"
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
	x25519, err := dh.FromString("25519")
	require.NotNil(t, x25519, "missing 25519")
	require.Nil(t, err, "should not return an error")

	x448, err := dh.FromString("448")
	require.NotNil(t, x448, "missing 448")
	require.Nil(t, err, "should not return an error")

	secp256k1, err := dh.FromString("secp256k1")
	require.NotNil(t, secp256k1, "missing secp256k1")
	require.Nil(t, err, "should not return an error")

	// check return empty
	yy, err := dh.FromString("yy")
	require.Nil(t, yy, "yy does not exist, yet")
	require.NotNil(t, err, "should return an error")

	require.Equal(t, len("25519, 448, secp256k1"), len(dh.SupportedCurves()),
		"curve 25519, 448 and secp256k1 should be returned")
}

func ExampleFromString() {
	// use the curve25519
	x25519, _ := dh.FromString("25519")
	fmt.Println(x25519)

	// use the curve448
	x448, _ := dh.FromString("448")
	fmt.Println(x448)

	// use the secp256k1
	secp256k1, _ := dh.FromString("secp256k1")
	fmt.Println(secp256k1)
}
