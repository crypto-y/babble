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

func (s *hashSha512) Hash(data []byte) []byte {
	s.New().Write(data)
	return s.h.Sum(nil)
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

func init() {
	var noiseSha512 Hash = &hashSha512{
		name: "SHA512",
		h:    sha512.New(),
	}
	Register(noiseSha512.String(), noiseSha512)
}
