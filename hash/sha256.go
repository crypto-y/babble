package hash

import (
	"crypto/sha256"
	"hash"
)

type hashSha256 struct {
	name string
	h    hash.Hash
}

// BlockLen for sha256 should be 64.
func (s *hashSha256) BlockLen() int {
	return s.H().BlockSize()
}

func (s *hashSha256) H() hash.Hash {
	return s.h
}

func (s *hashSha256) Hash(data []byte) []byte {
	s.H().Write(data)
	return s.h.Sum(nil)
}

// HashLen for sha256 should be 32.
func (s *hashSha256) HashLen() int {
	return s.H().Size()
}

func (s *hashSha256) String() string {
	return s.name
}

func (s *hashSha256) Reset() {
	s.H().Reset()
}

func init() {
	var noiseSha256 Hash = &hashSha256{
		name: "SHA256",
		h:    sha256.New(),
	}
	Register(noiseSha256.String(), noiseSha256)
}
