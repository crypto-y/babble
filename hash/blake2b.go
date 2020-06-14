package hash

import (
	"hash"

	"golang.org/x/crypto/blake2b"
)

type hashBLAKE2b struct {
	name string
}

// BlockLen for BLAKE2b should be 128.
func (s *hashBLAKE2b) BlockLen() int {
	return blake2b.BlockSize
}

func (s *hashBLAKE2b) New() hash.Hash {
	blake2bHash, _ := blake2b.New512(nil)
	return blake2bHash
}

// HashLen for BLAKE2b should be 64.
func (s *hashBLAKE2b) HashLen() int {
	return blake2b.Size
}

func (s *hashBLAKE2b) String() string {
	return s.name
}

func newBlake2b() Hash {
	return &hashBLAKE2b{name: "BLAKE2b"}
}

func init() {
	Register("BLAKE2b", newBlake2b)
}
