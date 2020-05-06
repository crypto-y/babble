// This is an implemention for demonstration only.
package main

import (
	"encoding/hex"
	"fmt"
	"hash"

	"golang.org/x/crypto/sha3"

	noiseHash "github.com/yyforyongyu/babble/hash"
)

type hashSha3 struct {
	name string
	h    hash.Hash
}

func (s *hashSha3) BlockLen() int {
	return s.New().BlockSize()
}

func (s *hashSha3) New() hash.Hash {
	return sha3.New512()
}

func (s *hashSha3) HashLen() int {
	return s.New().Size()
}

func (s *hashSha3) String() string {
	return s.name
}

func (s *hashSha3) Reset() {
	s.h.Reset()
}

func newSha3() noiseHash.Hash {
	return &hashSha3{
		name: "SHA3",
		h:    sha3.New512(),
	}
}

func main() {
	// register SHA3
	noiseHash.Register("SHA3", newSha3)

	noiseSha3, _ := noiseHash.FromString("SHA3")

	fmt.Println("sha3 block length: ", noiseSha3.BlockLen())
	fmt.Println("sha3 hash length: ", noiseSha3.HashLen())

	message := []byte("noise")
	h := noiseSha3.New()
	h.Write(message)
	digest := h.Sum(nil)
	fmt.Println("the output for 'noise' is: ", hex.EncodeToString(digest))
}
