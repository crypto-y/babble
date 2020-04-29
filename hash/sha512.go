package hash

import (
	"crypto/sha512"
	"hash"
)

type hashSha512 struct {
	name string
	h    hash.Hash
}

// BlockLen for sha512 should be 128.
func (s *hashSha512) BlockLen() int {
	return s.New().BlockSize()
}

func (s *hashSha512) New() hash.Hash {
	return s.h
}

// HashLen for sha512 should be 64.
func (s *hashSha512) HashLen() int {
	return s.New().Size()
}

func (s *hashSha512) String() string {
	return s.name
}

func (s *hashSha512) Reset() {
	s.New().Reset()
}

func newSha512() Hash {
	return &hashSha512{
		name: "SHA512",
		h:    sha512.New(),
	}
}

func init() {
	Register("SHA512", newSha512)
}
