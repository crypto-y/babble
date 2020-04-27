package noise

import (
	"testing"

	"github.com/stretchr/testify/require"
)

type testConfig struct {
	pattern string
	curve   string
	cipher  string
	hash    string
}

func TestParseProtocolName(t *testing.T) {
	unsupported := "YY"
	testParams := []struct {
		name         string
		protocolName string
		expectedErr  error
		config       *testConfig
	}{
		{
			"parse a normal protocol name",
			"Noise_XX_25519_AESGCM_SHA256",
			nil,
			&testConfig{"XX", "25519", "AESGCM", "SHA256"},
		},
		{
			"parse a protocol name with pattern modifiers",
			"Noise_XXfallback+psk0_25519_AESGCM_SHA256",
			nil,
			&testConfig{"XX", "25519", "AESGCM", "SHA256"},
		},
		{
			"parse name with wrong prefix",
			"YYois_XX_25519_AESGCM_SHA256",
			ErrProtocolInvalidName,
			nil,
		},
		{
			"parse name with wrong number of components",
			"Noise_YY_XX_25519_AESGCM_SHA256",
			ErrProtocolInvalidName,
			nil,
		},
		{
			"parse name with unsupported pattern",
			"Noise_YY_25519_AESGCM_SHA256",
			errInvalidComponent(unsupported),
			nil,
		},
		{
			"parse name with unsupported curve",
			"Noise_XX_YY_AESGCM_SHA256",
			errInvalidComponent(unsupported),
			nil,
		},
		{
			"parse name with unsupported cipher",
			"Noise_XX_25519_YY_SHA256",
			errInvalidComponent(unsupported),
			nil,
		},
		{
			"parse name with unsupported hash",
			"Noise_XX_25519_AESGCM_YY",
			errInvalidComponent(unsupported),
			nil,
		},
	}
	for _, tt := range testParams {
		t.Run(tt.name, func(t *testing.T) {
			c, err := parseProtocolName(tt.protocolName)
			require.Equal(
				t, tt.expectedErr, err, "error returned not match")

			if tt.config != nil {
				require.Equal(
					t, tt.config.pattern, c.pattern.String(),
					"pattern not match")
				require.Equal(
					t, tt.config.curve, c.curve.String(), "curve not match")
				require.Equal(
					t, tt.config.hash, c.hash.String(), "hash not match")
				require.Equal(
					t, tt.config.cipher, c.cipher.String(), "cipher not match")

			} else {
				require.Nil(t, tt.config, "should return a nil")
			}

		})
	}

}
