// Package hash implements the hash functions specified in the noise
// protocol.
//
// It currently supports four hash functions: SHA256, SHA512, BLAKE2a, and
// BLAKE2s.
package hash

import (
	"fmt"
	"hash"
	"strings"
)

var (
	supportedHashes = map[string]NewHash{}
)

// NewHash returns an instance of Hash.
type NewHash func() Hash

// Hash defines a hash interface specified by the noise specs.
type Hash interface {
	fmt.Stringer

	// BlockLen returns a constant specifying the size in bytes that the hash
	// function uses internally to divide its input for iterative processing.
	// This is needed to use the hash function with HMAC.
	BlockLen() int

	// New returns the hash function used.
	New() hash.Hash

	// HashLen returns a constant specifying the size in bytes of the hash
	// output. Must be 32 or 64.
	HashLen() int

	// Reset resets the Hash to its initial state.
	Reset()
}

// FromString uses the provided hash name, s, to query a built-in hash.
func FromString(s string) (Hash, error) {
	if supportedHashes[s] != nil {
		return supportedHashes[s](), nil
	}
	return nil, errUnsupported(s)
}

// Register updates the supported hashes used in package hash.
func Register(s string, new NewHash) {
	// TODO: check registry

	// check the Hash interface is matched
	var _ Hash = new()

	supportedHashes[s] = new
}

// SupportedHashes gives the names of all the hashs registered. If no new
// hashs are registered, it returns a string as "AESGCM, ChaChaPoly", orders
// not preserved.
func SupportedHashes() string {
	keys := make([]string, 0, len(supportedHashes))
	for k := range supportedHashes {
		keys = append(keys, k)
	}
	return strings.Join(keys, ", ")
}

func errUnsupported(s string) error {
	return fmt.Errorf("hash: %s is unsupported", s)
}
