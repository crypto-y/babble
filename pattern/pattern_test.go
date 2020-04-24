package pattern

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSetUp(t *testing.T) {
	supported := []string{
		// 3 oneway patterns
		"N", "K", "X",
		// 12 interactive patterns
		"NN", "KN", "NK", "KK", "NX", "KX", "XN", "IN", "XK", "IK", "XX", "IX",
		// 23 deffered patterns
		"NK1", "NX1", "X1N", "X1K", "XK1", "X1K1", "X1X", "XX1", "X1X1", "K1N",
		"K1K", "KK1", "K1K1", "K1X", "KX1", "K1X1", "I1N", "I1K", "IK1", "I1K1",
		"I1X", "IX1", "I1X1",
	}
	// check supported patterns
	//
	// one-way
	n, err := FromString("N")
	require.NotNil(t, n, "missing N")
	require.Nil(t, err, "should not return an error")
	require.Nil(t, n.Modifier, "should have no modifiers attached")

	x, err := FromString("X")
	require.NotNil(t, x, "missing X")
	require.Nil(t, err, "should not return an error")

	k, err := FromString("K")
	require.NotNil(t, k, "missing K")
	require.Nil(t, err, "should not return an error")

	// check return empty
	yy, err := FromString("yy")
	require.Nil(t, yy, "yy does not exist, yet")
	require.NotNil(t, err, "should return an error")

	require.Equal(t, len(strings.Join(supported, ", ")),
		len(SupportedPatterns()),
		"supported patterns should be 3+12+23=38")

	// mount a psk modifier
	n, err = FromString("Npsk0")
	require.NotNil(t, n, "missing N")
	require.Nil(t, err, "should not return an error")
	require.Equal(t, &Modifier{PskIndexes: []int{0}}, n.Modifier,
		"modifier returned not match")

	// the mounted modifier should not affect the old pattern
	n, err = FromString("N")
	require.Nil(t, err, "should not return an error")
	require.Nil(t, n.Modifier, "modifier should be nil")

	// mount a wrong modifier
	n, err = FromString("Npsk")
	require.Nil(t, n, "should return nil")
	require.NotNil(t, err, "should return an error")
}

func TestRegister(t *testing.T) {
	testParams := []struct {
		name        string
		patternName string
		pattern     string
		hasErr      bool
	}{
		{"register new pattern with pre", "NXX", `
			<- s
			...
			-> e, es
		`, false},
		{"register new pattern", "NXX1", `
			-> e
			<- e, ee
		`, false},
		{"wrong pattern name", "nxx", `
			-> e
			<- e, ee
		`, true},
		{"wrong pattern format", "NKXI", `
			<- s
			...
			...
			-> e, es
		`, true},
		{"wrong pre message format", "NXX3", `
			<- s, s
			...
			-> e, es
		`, true},
		{"wrong message format", "NXX4", `
			-> e, se
			<- e, ee
		`, true},
		{"register pattern with fallback", "NX1fallback", `
			-> e
		`, false},
		{"missing modifier name", "NX2psk", `
			-> e
		`, true},
		{"missing psk token", "NX2psk0", `
			-> e
		`, true},
		{"valid psk format", "NX3psk0", `
			-> psk, e
		`, false},
		{"wrong psk index length", "NX4psk1", `
			-> psk, e
		`, true},
		{"wrong psk ending position", "NX5psk1", `
			-> e
			<- psk, e
		`, true},
		{"wrong psk line position", "NX6psk0", `
			-> e, psk
			<- e
		`, true},
	}

	for _, tt := range testParams {
		t.Run(tt.name, func(t *testing.T) {
			err := Register(tt.patternName, tt.pattern)
			hp, _ := FromString(tt.patternName)
			if tt.hasErr {
				require.NotNil(t, err, "should return an error")
				require.Nil(t, hp, "should not return a pattern")
			} else {
				require.Nil(t, err, "should return no error")
				require.NotNil(t, hp, "pattern should exist")
				require.Equal(t, tt.pattern, hp.Pattern, "pattern not match")
				require.Equal(t, tt.patternName, hp.String(), "name not match")
			}
		})
	}
}

func TestParseModifiers(t *testing.T) {
	testParams := []struct {
		name         string
		modifierName string
		errExpected  error
		modExpected  *Modifier
	}{
		{"parse a name with no modifers", "", nil, nil},
		{"parse a name with a fallback modifiers", "fallback", nil, &Modifier{
			Fallback: true},
		},
		{"parse a name with a psk modifiers", "psk0", nil, &Modifier{
			PskIndexes: []int{0}},
		},
		{"parse a name with multiple modifiers", "psk0+psk1+fallback",
			nil, &Modifier{
				Fallback:   true,
				PskIndexes: []int{0, 1}},
		},
		{"parse a name with wrong fallback", "fallbak",
			errInvalidModifierName, nil,
		},
		{"parse a name with wrong psk missing index", "psk",
			errInvalidModifierName, nil,
		},
		{"parse a name with wrong psk wrong index", "psks",
			errInvalidModifierName, nil,
		},
	}

	for _, tt := range testParams {
		t.Run(tt.name, func(t *testing.T) {
			hp := &HandshakePattern{}
			err := hp.mountModifiers(tt.modifierName)
			require.Equal(t, tt.errExpected, err, "error returned not match")
			require.Equal(t, tt.modExpected, hp.Modifier,
				"modifiers returned not match")
		})
	}
}

func ExampleRegister() {
	// Register a psk0 with NK
	name := "NKpsk0"
	rawPattern := `
		<- s
		...
		-> psk, e, es
		<- e, ee`

	// Register will validate the pattern, if invalid, an error is returned.
	err := Register(name, rawPattern)
	if err != nil {
		fmt.Println(err)
	}
}

func ExampleFromString() {
	// use the pattern NX
	p, _ := FromString("NX")
	fmt.Println(p)
}
