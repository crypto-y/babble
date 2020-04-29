package hash

import (
	"hash"

	"golang.org/x/crypto/blake2b"
)

type hashBLAKE2b struct {
	name string
	h    hash.Hash
}

// BlockLen for BLAKE2b should be 128.
func (s *hashBLAKE2b) BlockLen() int {
	return s.New().BlockSize()
}

func (s *hashBLAKE2b) New() hash.Hash {
	return s.h
}

// HashLen for BLAKE2b should be 64.
func (s *hashBLAKE2b) HashLen() int {
	return s.New().Size()
}

func (s *hashBLAKE2b) String() string {
	return s.name
}

func (s *hashBLAKE2b) Reset() {
	s.New().Reset()
}

func newBlake2b() Hash {
	blake2bHash, _ := blake2b.New512(nil)
	return &hashBLAKE2b{
		name: "BLAKE2b",
		h:    blake2bHash,
	}
}

func init() {
	Register("BLAKE2b", newBlake2b)
}
