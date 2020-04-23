package noise

// import (
// 	"errors"
// 	"fmt"
// 	"strings"

// 	"github.com/yyforyongyu/noise/cipher"
// 	"github.com/yyforyongyu/noise/dh"
// 	"github.com/yyforyongyu/noise/hash"
// 	"github.com/yyforyongyu/noise/pattern"
// )

// var NoisePrefix = "Noise_"

// // TODO: remove
// var DHFunc = "448"
// var CipherFunc = "ChaChaPoly"
// var HashFunc = "SHA256"

// // To produce a Noise protocol name for Initialize() you concatenate the ASCII
// // string "Noise_" with four underscore-separated name sections which
// // sequentially name the handshake pattern, the DH functions, the cipher
// // functions, and then the hash functions. The resulting name must be 255 bytes
// // or less.
// func createNoiseProtocolName(handshakePattern string) []byte {
// name := fmt.Sprintf(
// 	"%s_%s_%s_%s_%s", NoisePrefix, handshakePattern,
// 	DHFunc, CipherFunc, HashFunc)
// 	return []byte(name)
// }

// var messagePatternTokens = []string{"e", "s", "ee", "es", "se", "ss", "psk"}
// var preMessagePatterns = []string{"e", "s", "e, s", ""}

// var (
// 	ErrProtocolNotSupported   = errors.New("protocol not supported")
// 	ErrProtocolInvalidName    = errors.New("invalid potocol name")
// 	ErrProtocolMissingPattern = errors.New("missing customized pattern")
// )

// type Protocol struct {
// 	DH      dh.DH
// 	Cipher  cipher.Cipher
// 	Hash    hash.Hash
// 	Pattern *pattern.HandshakePattern
// }

// const protocolPrefix = "Noise"

// // NewProtocol
// //
// func NewProtocol(s string, p string) (*Protocol, error) {
// 	// A valid name, such as "Noise_N_25519_ChaChaPoly_BLAKE2s", must have five
// 	// components.
// 	// see https://noiseprotocol.org/noise.html#protocol-names-and-modifiers
// 	// TODO: implement more strict checking
// components := strings.Split(s, "_")
// if len(components) != 5 || components[0] != protocolPrefix {
// 	return nil, ErrProtocolInvalidName
// }

// 	handshakePattern := pattern.FromString(components[1])
// 	var err error
// 	if handshakePattern == nil {
// 		// When using a non-built-in handshake pattern, a customized pattern
// 		// must be supplied.
// 		if p == "" {
// 			return nil, ErrProtocolMissingPattern
// 		}

// 		handshakePattern, err = pattern.NewHandshakePattern(components[1], p)
// 		if err != nil {
// 			return nil, ErrProtocolNotSupported
// 		}
// 	}

// 	pr := &Protocol{
// 		Pattern: &handshakePattern,
// 		// DH:      FromString(components[2]),
// 		// Cipher:  FromString(components[3]),
// 		// Hash:    FromString(components[4]),
// 	}

// 	// TODO: detailed error messages
// 	if pr.Pattern == nil || pr.DH == nil || pr.Cipher == nil || pr.Hash == nil {
// 		return nil, ErrProtocolNotSupported
// 	}

// 	return p, nil
// }

// func GetHandshakeHash() ([]byte, error) {
// 	return nil, nil
// }
