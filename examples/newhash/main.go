package main

import (
	"encoding/hex"
	"fmt"
	"hash"

	"golang.org/x/crypto/sha3"

	noiseHash "github.com/yyforyongyu/noise/hash"
)

type hashSha3 struct {
	name string
	h    hash.Hash
}

func (s *hashSha3) BlockLen() int {
	return s.New().BlockSize()
}

func (s *hashSha3) New() hash.Hash {
	return s.h
}

func (s *hashSha3) Hash(data []byte) []byte {
	s.New().Write(data)
	return s.h.Sum(nil)
}

func (s *hashSha3) HashLen() int {
	return s.New().Size()
}

func (s *hashSha3) String() string {
	return s.name
}

func (s *hashSha3) Reset() {
	s.New().Reset()
}

func main() {
	var noiseSha3 noiseHash.Hash = &hashSha3{
		name: "SHA3",
		h:    sha3.New512(),
	}
	noiseHash.Register(noiseSha3.String(), noiseSha3)

	fmt.Println("sha3 block length: ", noiseSha3.BlockLen())
	fmt.Println("sha3 hash length: ", noiseSha3.HashLen())

	message := []byte("noise")
	digest := noiseSha3.Hash(message)
	fmt.Println("the output for 'noise' is: ", hex.EncodeToString(digest))
}
