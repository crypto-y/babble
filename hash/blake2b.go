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

func (s *hashBLAKE2b) Hash(data []byte) []byte {
	s.New().Write(data)
	return s.h.Sum(nil)
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

func init() {
	var blake2bHash, _ = blake2b.New512(nil)
	var noiseBLAKE2b Hash = &hashBLAKE2b{
		name: "BLAKE2b",
		h:    blake2bHash,
	}
	Register(noiseBLAKE2b.String(), noiseBLAKE2b)
}
