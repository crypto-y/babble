package dh_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yyforyongyu/noise/dh"
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

func TestFromString(t *testing.T) {
	// check supported curves
	require.Equal(t, dh.X25519, dh.FromString("25519"), "missing 25519")
	require.Equal(t, dh.X448, dh.FromString("448"), "missing 448")
	require.Equal(
		t, dh.Secp256k1, dh.FromString("secp256k1"), "missing secp256k1")

	// check return empty
	require.Nil(t, dh.FromString("yy"), "yy does not exist, yet")
}
