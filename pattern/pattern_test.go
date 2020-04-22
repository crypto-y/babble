package pattern_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yyforyongyu/noise/pattern"
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
	n, err := pattern.FromString("N")
	require.NotNil(t, n, "missing N")
	require.Nil(t, err, "should not return an error")

	x, err := pattern.FromString("X")
	require.NotNil(t, x, "missing X")
	require.Nil(t, err, "should not return an error")

	k, err := pattern.FromString("K")
	require.NotNil(t, k, "missing K")
	require.Nil(t, err, "should not return an error")

	// check return empty
	yy, err := pattern.FromString("yy")
	require.Nil(t, yy, "yy does not exist, yet")
	require.NotNil(t, err, "should return an error")

	require.Equal(t, len(strings.Join(supported, ", ")),
		len(pattern.SupportedPatterns()),
		"supported patterns should be 3+12+23=38")
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
	}

	for _, tt := range testParams {
		t.Run(tt.name, func(t *testing.T) {
			err := pattern.Register(tt.patternName, tt.pattern)
			hp, _ := pattern.FromString(tt.patternName)
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

func ExampleRegister() {
	// Define your own name and pattern.
	name := "NXdumb"
	rawPattern := `
		-> e
		<- e, ee, se, s, es`

	// Register will validate the pattern, if invalid, an error is returned.
	err := pattern.Register(name, rawPattern)
	if err != nil {
		fmt.Println(err)
	}
}

func ExampleFromString() {
	// use the pattern NX
	p, _ := pattern.FromString("NX")
	fmt.Println(p)
}
