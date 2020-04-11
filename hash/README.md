# Hash Functions
This package implements the hash functions specified in the [noise protocol framework](https://noiseprotocol.org).



# Built-in Hash Functions
Four hash functions are supported, as specified in the [noise specs](https://noiseprotocol.org/noise.html#the-sha256-hash-function).

1. [SHA256](https://en.wikipedia.org/wiki/SHA-2)
2. [SHA512](https://en.wikipedia.org/wiki/SHA-2)
3. [BLAKE2b](https://en.wikipedia.org/wiki/BLAKE_(hash_function))
4. [BLAKE2s](https://en.wikipedia.org/wiki/BLAKE_(hash_function))



# Customize Hash Functions

To create your own hash function, you'll need to implement the interface specified in [`hash.go`](https://github.com/yyforyongyu/noise/blob/master/hash/hash.go). Once implemented, you need to register it using `Register(Name, Hash)`.

An example customized implementation, which implements the `SHA3`.

```go
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
	return s.H().BlockSize()
}

func (s *hashSha3) H() hash.Hash {
	return s.h
}

func (s *hashSha3) Hash(data []byte) []byte {
	s.H().Write(data)
	return s.h.Sum(nil)
}

func (s *hashSha3) HashLen() int {
	return s.H().Size()
}

func (s *hashSha3) String() string {
	return s.name
}

func (s *hashSha3) Reset() {
	s.H().Reset()
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
```

