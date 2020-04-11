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
	return s.H().BlockSize()
}

func (s *hashSha512) H() hash.Hash {
	return s.h
}

func (s *hashSha512) Hash(data []byte) []byte {
	s.H().Write(data)
	return s.h.Sum(nil)
}

// HashLen for sha512 should be 64.
func (s *hashSha512) HashLen() int {
	return s.H().Size()
}

func (s *hashSha512) String() string {
	return s.name
}

func (s *hashSha512) Reset() {
	s.H().Reset()
}

func init() {
	var noiseSha512 Hash = &hashSha512{
		name: "SHA512",
		h:    sha512.New(),
	}
	Register(noiseSha512.String(), noiseSha512)
}
