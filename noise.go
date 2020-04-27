package noise

import (
	"errors"
	"fmt"
	"strings"

	"github.com/yyforyongyu/noise/cipher"
	"github.com/yyforyongyu/noise/dh"
	"github.com/yyforyongyu/noise/hash"
	"github.com/yyforyongyu/noise/pattern"
)

const (
	NoisePrefix = "Noise"
)

var (
	ErrProtocolInvalidName  = errors.New("invalid potocol name")
	ErrProtocolNotSupported = errors.New("protocol not supported")
)

func errInvalidComponent(c string) error {
	return fmt.Errorf("component '%s' is not supported", c)
}

type ProtocolConfig struct {
	pattern *pattern.HandshakePattern
	curve   dh.Curve
	cipher  cipher.AEAD
	hash    hash.Hash
}

// func NewProtocol(name string) (*handshakeState, error) {
// 	return nil, nil
// }

// parseProtocolName takes a full protocol name and parse out the four
// components - pattern, curve, hash and cipher.
func parseProtocolName(s string) (*ProtocolConfig, error) {
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

	return &ProtocolConfig{
		pattern: p,
		curve:   d,
		hash:    h,
		cipher:  c,
	}, nil
}
