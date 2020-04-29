// Package noise implements the Noise Protocol Framework.
//  https://noiseprotocol.org/
// Supported patterns:
//  3 oneway patterns, 12 interactive patterns and 23 deffered patterns, with
//  PSK mode supported.
// Supported dh curves:
//  curve448, curve25519 and secp256k1
// Supported ciphers:
//  ChaCha20-Poly1305 and AESGCM
// Supported hash functions:
//  SHA256, SHA512, BLAKE2b and BLAKE2s
package noise

import (
	"errors"
	"fmt"
	"strings"

	"github.com/yyforyongyu/noise/cipher"
	"github.com/yyforyongyu/noise/dh"
	"github.com/yyforyongyu/noise/hash"
	"github.com/yyforyongyu/noise/pattern"
	"github.com/yyforyongyu/noise/rekey"
)

// NoisePrefix is the mandatory prefix defined by the noise protocol framework.
const NoisePrefix = "Noise"

const (
	defaultRekeyInterval = 10000
	defaultResetNonce    = true
)

var (
	// ErrInvalidRekeyInterval is returned when interval is 0.
	ErrInvalidRekeyInterval = errors.New("rekey interval cannot be 0")

	// ErrMissingConfig is returned when no config file is provided.
	ErrMissingConfig = errors.New("missing config")

	// ErrProtocolInvalidName is returned when protocol name is wrong.
	ErrProtocolInvalidName = errors.New("invalid potocol name")

	// ErrProtocolNotSupported is returned when unsupported components used.
	// ErrProtocolNotSupported = errors.New("protocol not supported")
)

// DefaultRekeyerConfig is used for creating the default rekey manager.
type DefaultRekeyerConfig struct {
	// Interval specifies the number of messages to be sent before a rekey is
	// performed.
	Interval uint64

	// ResetNonce decides whether to reset the cipher nonce to zero when a rekey
	// is performed.
	ResetNonce bool
}

// ProtocolConfig is used for constructing a new handshake state.
type ProtocolConfig struct {
	// Name is the protocol name defined by the noise specs, e.g.,
	// Noise_XX_25519_AESGCM_SHA256
	Name string

	// Initiator specifies whether it's the handshake initiator
	Initiator bool

	// Prologue is an optional information to be used when creating the
	// handskake state. Both parties must provide identical prologue data,
	// otherwisethe handshake will fail due to a decryption error.
	Prologue string

	// RekeyerConfig is a config used for set up the default rekeyer. If Rekeyer
	// is set, this variable is ignored.
	RekeyerConfig *DefaultRekeyerConfig

	// Rekeyer is a rekey manager, which controls when/how a rekey should be
	// performed, and whether the cipher nonce should be reset.
	Rekeyer rekey.Rekeyer

	// LocalStaticPriv is the s from the noise spec. Only provide it when it's
	// needed by the message pattern, otherwise leave it empty.
	LocalStaticPriv []byte

	// LocalEphemeralPriv is the e from the noise spec. Only provide it when
	// it's needed by the message pattern, otherwise leave it empty.
	LocalEphemeralPriv []byte

	// RemoteStaticPub is the rs from the noise spec. Only provide it when it's
	// needed by the message pattern, otherwise leave it empty.
	RemoteStaticPub []byte

	// RemoteEphemeralPub is the re from the noise spec. Only provide it when
	// it's needed by the message pattern, otherwise leave it empty.
	RemoteEphemeralPub []byte

	// Psks is used to store the pre-shared symmetric keys used if both parties
	// have a 32-byte shared secret keys.
	Psks [][]byte

	// autoPadding is for internal usage, if true, required local keys will be
	// created automatically.
	autoPadding bool
}

// handshakeConfig is for internal usage.
type handshakeConfig struct {
	protocolName []byte
	prologue     []byte
	pattern      *pattern.HandshakePattern
	curve        dh.Curve
	cipher       cipher.AEAD
	hash         hash.Hash

	e  dh.PrivateKey
	s  dh.PrivateKey
	re dh.PublicKey
	rs dh.PublicKey
}

// NewProtocol creates a new handshake state with the specified name prologue,
// and initiator. It calls the NewProtocolWithConfig with a default config,
// in which,
//  - a default rekeyer is used, which resets the cipher key with an interval of
//  10000 and resets the nonce to be zero.
//
//  - if any local ephemeral/static or remote ephemeral/static keys are needed
//  by the message pattern prior to the creation of the handshake state, it will
//  create the corresponding keys automatically.
// NewProtocl doesn't support PSK mode, and specifying remote public keys prior
// to the creation of the handshake state, if needed, please use
// NewProtocolWithConfig instead.
func NewProtocol(name, prologue string,
	initiator bool) (*HandshakeState, error) {
	// name must not be empty
	if name == "" {
		return nil, ErrProtocolInvalidName
	}

	// parse handshake config
	hsc, err := parseProtocolName(name)
	if err != nil {
		return nil, err
	}
	// create a default rekeyer
	rekeyer := rekey.NewDefault(
		defaultRekeyInterval, hsc.cipher, defaultResetNonce)

	config := &ProtocolConfig{
		Name:        name,
		Prologue:    prologue,
		Initiator:   initiator,
		autoPadding: true,
		Rekeyer:     rekeyer,
	}
	return NewProtocolWithConfig(config)
}

// NewProtocolWithConfig creates a handshake state with parameters from a
// ProtocolConfig.
func NewProtocolWithConfig(config *ProtocolConfig) (*HandshakeState, error) {
	if config == nil {
		return nil, ErrMissingConfig
	}
	// name must not be empty
	name := config.Name
	if name == "" {
		return nil, ErrProtocolInvalidName
	}

	// parse handshake config
	hsc, err := parseProtocolName(name)
	if err != nil {
		return nil, err
	}

	// create a default rekeyer if no rekeyer is specified
	var rk rekey.Rekeyer
	if config.Rekeyer == nil {
		rc := config.RekeyerConfig
		// if no rekeyer config is provided, use the default parameters.
		if rc == nil {
			rk = rekey.NewDefault(defaultRekeyInterval, hsc.cipher, true)
		} else {
			i := rc.Interval
			if i == 0 {
				return nil, ErrInvalidRekeyInterval
			}
			rk = rekey.NewDefault(rc.Interval, hsc.cipher, rc.ResetNonce)
		}
	} else {
		rk = config.Rekeyer
	}

	// parse related keys
	if config.LocalStaticPriv != nil {
		s, err := hsc.curve.LoadPrivateKey(config.LocalStaticPriv)
		if err != nil {
			return nil, err
		}
		hsc.s = s
	}
	if config.LocalEphemeralPriv != nil {
		e, err := hsc.curve.LoadPrivateKey(config.LocalEphemeralPriv)
		if err != nil {
			return nil, err
		}
		hsc.e = e
	}
	if config.RemoteEphemeralPub != nil {
		re, err := hsc.curve.LoadPublicKey(config.RemoteEphemeralPub)
		if err != nil {
			return nil, err
		}
		hsc.re = re
	}
	if config.RemoteStaticPub != nil {
		rs, err := hsc.curve.LoadPublicKey(config.RemoteStaticPub)
		if err != nil {
			return nil, err
		}
		hsc.rs = rs
	}

	hsc.protocolName = []byte(config.Name)
	hsc.prologue = []byte(config.Prologue)

	// create cipher state, symmetric state and handshake state
	cs := newCipherState(hsc.cipher, rk)
	ss := newSymmetricState(cs, hsc.hash, hsc.curve)
	hs, err := newHandshakeState(
		hsc.protocolName, hsc.prologue,
		config.Psks, config.Initiator, ss, hsc.pattern,
		hsc.s, hsc.e, hsc.rs, hsc.re, config.autoPadding)
	if err != nil {
		return nil, err
	}

	return hs, nil
}

func errInvalidComponent(c string) error {
	return fmt.Errorf("component '%s' is not supported", c)
}

// parseProtocolName takes a full protocol name and parse out the four
// components - pattern, curve, hash and cipher.
func parseProtocolName(s string) (*handshakeConfig, error) {
	components := strings.Split(s, "_")
	if len(components) != 5 || components[0] != NoisePrefix {
		return nil, ErrProtocolInvalidName
	}

	// find pattern
	p, _ := pattern.FromString(components[1])
	if p == nil {
		return nil, errInvalidComponent(components[1])
	}

	// find dh curve
	d, _ := dh.FromString(components[2])
	if d == nil {
		return nil, errInvalidComponent(components[2])
	}

	// find cipher
	c, _ := cipher.FromString(components[3])
	if c == nil {
		return nil, errInvalidComponent(components[3])
	}

	// find hash func
	h, _ := hash.FromString(components[4])
	if h == nil {
		return nil, errInvalidComponent(components[4])
	}

	return &handshakeConfig{
		pattern: p,
		curve:   d,
		hash:    h,
		cipher:  c,
	}, nil
}
