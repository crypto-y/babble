package hash

import (
	"hash"

	"golang.org/x/crypto/blake2s"
)

type hashBLAKE2s struct {
	name string
}

// BlockLen for BLAKE2s should be 64.
func (s *hashBLAKE2s) BlockLen() int {
	return blake2s.BlockSize
}

func (s *hashBLAKE2s) New() hash.Hash {
	h, _ := blake2s.New256(nil)
	return h
}

// HashLen for BLAKE2s should be 32.
func (s *hashBLAKE2s) HashLen() int {
	return blake2s.Size
}

func (s *hashBLAKE2s) String() string {
	return s.name
}

func newBlake2s() Hash {
	return &hashBLAKE2s{name: "BLAKE2s"}
}

func init() {
	Register("BLAKE2s", newBlake2s)
}
