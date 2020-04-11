package hash

import (
	"hash"

	"golang.org/x/crypto/blake2s"
)

type hashBLAKE2s struct {
	name string
	h    hash.Hash
}

// BlockLen for BLAKE2s should be 64.
func (s *hashBLAKE2s) BlockLen() int {
	return s.New().BlockSize()
}

func (s *hashBLAKE2s) New() hash.Hash {
	return s.h
}

func (s *hashBLAKE2s) Hash(data []byte) []byte {
	s.New().Write(data)
	return s.h.Sum(nil)
}

// HashLen for BLAKE2s should be 32.
func (s *hashBLAKE2s) HashLen() int {
	return s.New().Size()
}

func (s *hashBLAKE2s) String() string {
	return s.name
}

func (s *hashBLAKE2s) Reset() {
	s.New().Reset()
}

func init() {
	var blake2sHash, _ = blake2s.New256(nil)
	var noiseBLAKE2s Hash = &hashBLAKE2s{
		name: "BLAKE2s",
		h:    blake2sHash,
	}
	Register(noiseBLAKE2s.String(), noiseBLAKE2s)
}
