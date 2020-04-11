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
	byte00 = []byte{0}
	byte01 = []byte{1}
	byte02 = []byte{2}
	byte03 = []byte{3}

	supportedHashes = map[string]Hash{}
)

// Hash defines a hash interface specified by the noise specs.
type Hash interface {
	fmt.Stringer

	// BlockLen returns a constant specifying the size in bytes that the hash
	// function uses internally to divide its input for iterative processing.
	// This is needed to use the hash function with HMAC.
	BlockLen() int

	// New returns the hash function used.
	New() hash.Hash

	// Hash uses some arbitrary-length data with a collision-resistant
	// cryptographic hash function and returns an output of HashLen bytes.
	Hash([]byte) []byte

	// HashLen returns a constant specifying the size in bytes of the hash
	// output. Must be 32 or 64.
	HashLen() int

	// Reset resets the Hash to its initial state.
	Reset()
}

// FromString uses the provided hash name, s, to query a built-in hash.
func FromString(s string) Hash {
	return supportedHashes[s]
}

// Register updates the supported hashes used in package hash.
func Register(s string, a Hash) {
	// TODO: check registry
	supportedHashes[s] = a
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
