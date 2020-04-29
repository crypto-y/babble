package babble

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	noiseCipher "github.com/yyforyongyu/babble/cipher"
	"github.com/yyforyongyu/babble/rekey"
)

func TestNewProtocolWithConfig(t *testing.T) {
	name := "Noise_XN_25519_AESGCM_SHA256"
	c, _ := noiseCipher.FromString("AESGCM")
	testInterval := uint64(100)
	testResetNonce := true
	rk := rekey.NewDefault(testInterval, c, testResetNonce)

	testParams := []struct {
		name               string
		config             *ProtocolConfig
		errExpected        error
		intervalExpected   uint64
		resetNonceExpected bool
	}{
		{"return error when config is nil", nil, ErrMissingConfig,
			testInterval, testResetNonce},
		{"return error when name is nil", &ProtocolConfig{},
			ErrProtocolInvalidName, testInterval, testResetNonce},
		{"return error when name is invalid", &ProtocolConfig{
			Name: "yy",
		}, ErrProtocolInvalidName, testInterval, testResetNonce},
		{"return error when interval is 0", &ProtocolConfig{
			Name:          name,
			RekeyerConfig: &DefaultRekeyerConfig{},
		}, ErrInvalidRekeyInterval, testInterval, testResetNonce},
		{"return error when loading local static", &ProtocolConfig{
			Name:            name,
			LocalStaticPriv: []byte{0},
		}, errors.New("private key is wrong: want 32 bytes, got 1 bytes"),
			testInterval, testResetNonce},
		{"return error when loading local ephemeral", &ProtocolConfig{
			Name:               name,
			LocalEphemeralPriv: []byte{0},
		}, errors.New("private key is wrong: want 32 bytes, got 1 bytes"),
			testInterval, testResetNonce},
		{"return error when loading remote static", &ProtocolConfig{
			Name:            name,
			RemoteStaticPub: []byte{0},
		}, errors.New("public key is wrong: want 32 bytes, got 1 bytes"),
			testInterval, testResetNonce},
		{"return error when loading remote ephemeral", &ProtocolConfig{
			Name:               name,
			RemoteEphemeralPub: []byte{0},
		}, errors.New("public key is wrong: want 32 bytes, got 1 bytes"),
			testInterval, testResetNonce},
		{"return error when missing keys", &ProtocolConfig{
			Name:      name,
			Initiator: true,
		}, errMissingKey("local static key"), testInterval, testResetNonce},
		{"return success", &ProtocolConfig{
			Name:            name,
			Initiator:       true,
			LocalStaticPriv: key[:],
		}, nil, defaultRekeyInterval, defaultResetNonce},
		{"test rekey config", &ProtocolConfig{
			Name:            name,
			Initiator:       true,
			LocalStaticPriv: key[:],
			RekeyerConfig:   &DefaultRekeyerConfig{Interval: testInterval},
		}, nil, testInterval, false},
		{"test using customized rekey", &ProtocolConfig{
			Name:            name,
			Initiator:       true,
			LocalStaticPriv: key[:],
			Rekeyer:         rk,
		}, nil, testInterval, testResetNonce},
		{"test loading keys from config", &ProtocolConfig{
			Name:               name,
			Initiator:          true,
			LocalStaticPriv:    key[:],
			LocalEphemeralPriv: key[:],
			RemoteEphemeralPub: key[:],
			RemoteStaticPub:    key[:],
			Rekeyer:            rk,
		}, errKeyNotEmpty("local ephemeral key"), testInterval, testResetNonce},
	}

	for _, tt := range testParams {
		t.Run(tt.name, func(t *testing.T) {
			hs, err := NewProtocolWithConfig(tt.config)
			require.Equal(t, tt.errExpected, err, "error not match")
			if tt.errExpected != nil {
				require.Nil(t, hs, "should not return an hs")
			} else {
				require.NotNil(t, hs, "should return an hs")
				require.Equal(t, tt.intervalExpected,
					hs.ss.cs.RekeyManger.Interval(),
					"rekey interval not match")
				require.Equal(t, tt.resetNonceExpected,
					hs.ss.cs.RekeyManger.ResetNonce(),
					"rekey reset nonce not match")
			}

		})
	}
}

func TestNewProtocol(t *testing.T) {
	name := "Noise_XN_25519_AESGCM_SHA256"

	testParams := []struct {
		name               string
		protocolName       string
		prologue           string
		Initiator          bool
		errExpected        error
		intervalExpected   uint64
		resetNonceExpected bool
	}{
		{"return error when name is empty", "", "", true,
			ErrProtocolInvalidName, defaultRekeyInterval, defaultResetNonce},
		{"return error when name is invalid", "yy", "", true,
			ErrProtocolInvalidName, defaultRekeyInterval, defaultResetNonce},
		{"return success", name, "", true,
			nil, defaultRekeyInterval, defaultResetNonce},
	}

	for _, tt := range testParams {
		t.Run(tt.name, func(t *testing.T) {
			hs, err := NewProtocol(tt.protocolName, tt.prologue, tt.Initiator)
			require.Equal(t, tt.errExpected, err, "error not match")
			if tt.errExpected != nil {
				require.Nil(t, hs, "no hs should be created")
			} else {
				require.NotNil(t, hs, "hs should be created")
				require.Equal(t, tt.intervalExpected,
					hs.ss.cs.RekeyManger.Interval(),
					"rekey interval not match")
				require.Equal(t, tt.resetNonceExpected,
					hs.ss.cs.RekeyManger.ResetNonce(),
					"rekey reset nonce not match")
			}
		})
	}
}

func TestParseProtocolName(t *testing.T) {
	type testConfig struct {
		pattern string
		curve   string
		cipher  string
		hash    string
	}

	unsupported := "YXY"
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
			"Noise_YXY_25519_AESGCM_SHA256",
			errInvalidComponent(unsupported),
			nil,
		},
		{
			"parse name with unsupported curve",
			"Noise_XX_YXY_AESGCM_SHA256",
			errInvalidComponent(unsupported),
			nil,
		},
		{
			"parse name with unsupported cipher",
			"Noise_XX_25519_YXY_SHA256",
			errInvalidComponent(unsupported),
			nil,
		},
		{
			"parse name with unsupported hash",
			"Noise_XX_25519_AESGCM_YXY",
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
